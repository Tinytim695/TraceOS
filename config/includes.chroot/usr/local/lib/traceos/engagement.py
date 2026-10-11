"""Authorized red, blue and purple engagement playbooks.

Playbooks build exact argument lists. They never invoke a shell and they
never include denial-of-service tooling. Running a playbook is a separate
step and requires an explicit authorization token.
"""
from __future__ import annotations

import ipaddress
import os
import shlex
import stat
from pathlib import Path
from urllib.parse import urlsplit

FORBIDDEN_COMMANDS = frozenset(
    {
        "hping",
        "hping3",
        "masscan",
        "zmap",
        "slowhttptest",
        "slowloris",
        "goldeneye",
        "mhddos",
        "bonesi",
    }
)
AUTH_SERVICES = frozenset(
    {"ssh", "ftp", "smb", "rdp", "http-get", "https-get", "ldap2", "mssql"}
)
MAX_SECRET_FILE_BYTES = 50 * 1024 * 1024
CANARY_TEXT = "TraceOS-PURPLE-CANARY\n"
CANARY_NAME = "purple-canary.txt"
DEFAULT_RULE = "/usr/share/traceos/rules/purple-canary.yar"
SNMP_COMMUNITIES = "/usr/share/traceos/snmp-public.txt"


def _domain(host: str) -> str:
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Enter a valid domain.") from exc
    labels = ascii_host.rstrip(".").split(".")
    if (
        not ascii_host
        or len(ascii_host) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    ):
        raise ValueError("Enter a valid domain.")
    return ascii_host.rstrip(".")


def _host(value: str) -> str:
    text = value.strip()
    if not text or text.startswith("-") or "://" in text or "/" in text:
        raise ValueError("Enter one host or IP address, not a URL or an option.")
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return _domain(text)


def _url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a full http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed.")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target port is invalid.") from exc
    _host(parsed.hostname)
    return parsed._replace(fragment="").geturl()


def _regular_file(value: str) -> str:
    path = Path(value).expanduser()
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("Select an existing regular file.") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("Select an existing regular file, not a link.")
    if info.st_size > MAX_SECRET_FILE_BYTES:
        raise ValueError("That file is larger than 50 MB. Use a scoped list.")
    return str(path)


def _render(argv: list[str], slots: dict[str, str]) -> list[str]:
    rendered = []
    for part in argv:
        value = part
        for key, replacement in slots.items():
            value = value.replace(key, replacement)
        rendered.append(value)
    command = Path(rendered[0]).name
    if command in FORBIDDEN_COMMANDS:
        raise ValueError(f"{command} is not available in TraceOS engagements.")
    return rendered


PLAYBOOKS: dict[str, dict] = {
    "red-external-recon": {
        "title": "External reconnaissance",
        "team": "red",
        "mode": "domain",
        "technique": "T1595",
        "expected": "DNS query logs and web proxy or access logs for the domain",
        "steps": [
            {"name": "Subfinder", "timeout": 180, "argv": ["subfinder", "-d", "{domain}", "-silent"]},
            {"name": "dnsx", "timeout": 120, "argv": ["dnsx", "-silent", "-d", "{domain}"]},
            {"name": "Naabu", "timeout": 180, "argv": ["naabu", "-host", "{domain}", "-top-ports", "100"]},
            {"name": "httpx", "timeout": 180, "argv": ["httpx", "-silent", "-u", "https://{domain}"]},
        ],
    },
    "red-web": {
        "title": "Web application assessment",
        "team": "red",
        "mode": "url",
        "technique": "T1190",
        "expected": "web server access log and any WAF or application alert",
        "steps": [
            {"name": "WhatWeb", "timeout": 120, "argv": ["whatweb", "{url}"]},
            {"name": "WAFW00F", "timeout": 120, "argv": ["wafw00f", "{url}"]},
            {
                "name": "Nuclei",
                "timeout": 300,
                "argv": [
                    "nuclei", "-u", "{url}", "-silent",
                    "-severity", "info,low,medium",
                    "-exclude-tags", "dos,fuzz,intrusive",
                ],
            },
            {"name": "Nikto", "timeout": 300, "argv": ["nikto", "-h", "{url}"]},
        ],
    },
    "red-tls": {
        "title": "TLS and certificate assessment",
        "team": "red",
        "mode": "url",
        "technique": "T1190",
        "expected": "TLS handshake logs on the target service",
        "steps": [
            {"name": "testssl", "timeout": 300, "argv": ["testssl.sh", "--quiet", "--color", "0", "{url}"]},
            {"name": "sslscan", "timeout": 180, "argv": ["sslscan", "{url}"]},
        ],
    },
    "red-ad-enum": {
        "title": "Active Directory enumeration",
        "team": "red",
        "mode": "host",
        "technique": "T1135",
        "expected": "Windows security log for SMB and LDAP access",
        "steps": [
            {"name": "NetExec SMB", "timeout": 180, "argv": ["nxc", "smb", "{host}"]},
            {"name": "enum4linux-ng", "timeout": 300, "argv": ["enum4linux-ng", "{host}"]},
            {"name": "NBTscan", "timeout": 60, "argv": ["nbtscan", "{host}"]},
            {"name": "SNMP system", "timeout": 60, "argv": ["onesixtyone", "-c", SNMP_COMMUNITIES, "{host}"]},
        ],
    },
    "red-credential-audit": {
        "title": "Scoped credential audit",
        "team": "red",
        "mode": "auth",
        "technique": "T1110",
        "expected": "authentication failure events, account lockout or source-host alert",
        "steps": [
            {
                "name": "Hydra",
                "timeout": 300,
                "argv": ["hydra", "-t", "4", "-f", "-I", "-L", "{users}", "-P", "{passwords}", "{service}://{host}"],
            },
        ],
    },
    "blue-detection": {
        "title": "Network detection proof",
        "team": "blue",
        "mode": "local",
        "technique": "T1040",
        "expected": "packet capture file and a valid Suricata configuration",
        "steps": [
            {"name": "Suricata config", "timeout": 120, "argv": ["suricata", "-T", "-c", "/etc/suricata/suricata.yaml"]},
            {"name": "tcpdump sample", "timeout": 90, "argv": ["tcpdump", "-i", "any", "-c", "20", "-n"]},
            {"name": "auditd status", "timeout": 30, "argv": ["auditctl", "-s"]},
        ],
    },
    "blue-host-audit": {
        "title": "Host defence audit",
        "team": "blue",
        "mode": "local",
        "technique": "T1082",
        "expected": "local audit findings for hardening, rootkits and file integrity",
        "steps": [
            {"name": "Lynis", "timeout": 600, "argv": ["lynis", "audit", "system", "--quick", "--no-colors"]},
            {"name": "chkrootkit", "timeout": 300, "argv": ["chkrootkit", "-q"]},
            {"name": "rkhunter", "timeout": 300, "argv": ["rkhunter", "--check", "--sk", "--nocolors", "--rwo"]},
        ],
    },
    "purple-canary": {
        "title": "Purple detection canary",
        "team": "purple",
        "mode": "local",
        "technique": "T1204",
        "expected": "YARA match on the case-local canary file",
        "steps": [
            {"name": "YARA canary", "timeout": 60, "argv": ["yara", "{rule}", "{canary}"]},
        ],
    },
}


def list_playbooks() -> list[dict[str, str]]:
    return [
        {
            "id": playbook_id,
            "title": spec["title"],
            "team": spec["team"],
            "mode": spec["mode"],
            "technique": spec["technique"],
        }
        for playbook_id, spec in PLAYBOOKS.items()
    ]


def build_playbook(
    playbook_id: str,
    target: str = "",
    users_file: str = "",
    passwords_file: str = "",
    service: str = "ssh",
    rule_path: str = "",
    canary_path: str = "",
) -> list[dict]:
    spec = PLAYBOOKS.get(playbook_id)
    if spec is None:
        raise ValueError(f"Unknown engagement: {playbook_id}")
    mode = spec["mode"]
    slots = {
        "{rule}": rule_path or os.environ.get("TRACEOS_PURPLE_RULE", DEFAULT_RULE),
        "{canary}": canary_path,
    }
    if mode == "url":
        slots["{url}"] = _url(target)
    elif mode == "domain":
        slots["{domain}"] = _domain(target.strip())
    elif mode == "host":
        slots["{host}"] = _host(target)
    elif mode == "auth":
        chosen = service.strip().lower()
        if chosen not in AUTH_SERVICES:
            raise ValueError("Choose one allowed service: " + ", ".join(sorted(AUTH_SERVICES)))
        slots["{host}"] = _host(target)
        slots["{service}"] = chosen
        slots["{users}"] = _regular_file(users_file)
        slots["{passwords}"] = _regular_file(passwords_file)
    elif mode != "local":
        raise ValueError(f"Unknown engagement mode: {mode}")

    steps = []
    for step in spec["steps"]:
        argv = _render(list(step["argv"]), slots)
        if playbook_id == "red-web" and step["name"] == "Nuclei":
            if "dos,fuzz,intrusive" not in argv:
                raise ValueError("Nuclei must exclude denial-of-service and intrusive tags.")
        steps.append(
            {
                "name": step["name"],
                "timeout": int(step["timeout"]),
                "argv": argv,
                "technique": spec["technique"],
                "expected": spec["expected"],
                "team": spec["team"],
                "title": spec["title"],
            }
        )
    return steps


def assert_no_forbidden_tools() -> None:
    for playbook_id in PLAYBOOKS:
        if playbook_id == "red-credential-audit":
            continue
        steps = build_playbook(
            playbook_id,
            "https://example.test" if PLAYBOOKS[playbook_id]["mode"] == "url" else "example.test",
            rule_path="/tmp/purple-canary.yar",
            canary_path="/tmp/purple-canary.txt",
        )
        for step in steps:
            if Path(step["argv"][0]).name in FORBIDDEN_COMMANDS:
                raise AssertionError(step["argv"][0])
