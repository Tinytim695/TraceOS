#!/usr/bin/env python3
"""TraceOS Investigation Centre subprocess/tool metadata helpers."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from actions import ActionRequest, ActionScope


@dataclass(frozen=True)
class ToolSpec:
    key: str
    command: str
    purpose: str
    external: bool = True


TOOLS = (
    ToolSpec("sherlock", "sherlock", "username discovery"),
    ToolSpec("maigret", "maigret", "username investigation"),
    ToolSpec("h8mail", "h8mail", "email OSINT"),
    ToolSpec("blackbird", "blackbird", "username/email search"),
    ToolSpec("whois", "whois", "domain/IP registration lookup"),
    ToolSpec("dns", "dig", "DNS inspection"),
    ToolSpec("nmap", "nmap", "authorized network service discovery"),
)

_LOOKUP_COMMANDS = {"whois": "whois", "dns": "dig"}
_LABEL_RE = re.compile(r"^[A-Za-z0-9-]+$")
_DNS_STATUS_RE = re.compile(
    r"^;;\s*[^\n]*\bstatus:\s*([A-Z]+)",
    re.IGNORECASE | re.MULTILINE,
)
_DNS_ANSWER_RE = re.compile(
    r"^;;\s*flags:.*\bANSWER:\s*(\d+)",
    re.IGNORECASE | re.MULTILINE,
)


def validate_basic_lookup_target(target: str) -> str:
    """Validate a domain/IP target for passive WHOIS/DNS GUI/basic CLI mode."""
    if not isinstance(target, str):
        raise ValueError("target must be text")
    value = target.strip()
    if not value:
        raise ValueError("target is required")
    if value.startswith("-"):
        raise ValueError("target must not start with '-'")
    if any(char.isspace() for char in value):
        raise ValueError("target must not contain whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("target contains a control character")
    if any(marker in value for marker in ("://", "@", "/", "?", "#", "\\")):
        raise ValueError("target must be a bare domain or IP address")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    candidate = value.rstrip(".")
    if not candidate or len(candidate) > 253:
        raise ValueError("target is not a valid domain name")

    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target is not a valid domain name") from exc

    if len(ascii_name) > 253:
        raise ValueError("target is not a valid domain name")
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not _LABEL_RE.fullmatch(label)
        for label in labels
    ):
        raise ValueError("target is not a valid domain name")
    return ascii_name


def build_basic_lookup_command(tool: str, target: str) -> list[str]:
    """Build a validated argv for a basic passive WHOIS/DNS lookup."""
    try:
        command = _LOOKUP_COMMANDS[tool]
    except KeyError as exc:
        raise ValueError(f"unsupported basic lookup tool: {tool}") from exc
    return [command, validate_basic_lookup_target(target)]


class BasicLookupAdapter:
    """Small immutable adapter contract for the initial passive lookups."""

    __slots__ = (
        "key",
        "display_name",
        "command",
        "purpose",
        "network",
        "_version_args",
    )

    def __init__(
        self,
        key: str,
        display_name: str,
        command: str,
        purpose: str,
        network: bool,
        version_args: tuple[str, ...],
    ) -> None:
        self.key = key
        self.display_name = display_name
        self.command = command
        self.purpose = purpose
        self.network = network
        self._version_args = version_args

    def __setattr__(self, name: str, value: Any) -> None:
        if hasattr(self, name):
            raise AttributeError("BasicLookupAdapter instances are immutable")
        object.__setattr__(self, name, value)

    def available(self) -> bool:
        return shutil.which(self.command) is not None

    def version_argv(self) -> list[str]:
        return [self.command, *self._version_args]

    def validate_target(self, target: str) -> str:
        return validate_basic_lookup_target(target)

    def build_argv(self, target: str) -> list[str]:
        return [self.command, self.validate_target(target)]

    def parse_result(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
    ) -> dict[str, object]:
        if exit_code != 0:
            raise ValueError("result parser requires a successful tool exit")
        if self.key == "dns":
            return _parse_dns_result(stdout, stderr)
        return _parse_whois_result(stdout, stderr)


def _parse_whois_result(stdout: str, stderr: str) -> dict[str, object]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise ValueError("WHOIS produced no parseable output")

    lowered = "\n".join(lines).lower()
    no_data = any(
        marker in lowered
        for marker in ("no match", "not found", "no data", "no entries")
    )
    field_lines = [line for line in lines if ":" in line]
    if not field_lines and not no_data:
        raise ValueError("WHOIS output is not structurally parseable")

    return {
        "kind": "whois",
        "status": "NO_DATA" if no_data else "RESULT",
        "field_count": len(field_lines),
        "line_count": len(lines),
    }


def _parse_dns_result(stdout: str, stderr: str) -> dict[str, object]:
    status_match = _DNS_STATUS_RE.search(stdout)
    answer_match = _DNS_ANSWER_RE.search(stdout)
    if not status_match or not answer_match:
        raise ValueError("DNS output missing dig header status/count")

    rcode = status_match.group(1).upper()
    answer_count = int(answer_match.group(1))
    if rcode == "NXDOMAIN":
        status = "NXDOMAIN"
    elif rcode in {"SERVFAIL", "REFUSED", "FORMERR"}:
        status = "TOOL_ERROR"
    elif answer_count == 0:
        status = "NO_ANSWER"
    else:
        status = "ANSWER"

    return {
        "kind": "dns",
        "status": status,
        "answer_count": answer_count,
        "rcode": rcode,
    }


ADAPTERS: dict[str, BasicLookupAdapter] = {
    "whois": BasicLookupAdapter(
        "whois",
        "WHOIS",
        "whois",
        "domain/IP registration lookup",
        True,
        ("--version",),
    ),
    "dns": BasicLookupAdapter(
        "dns",
        "DNS",
        "dig",
        "DNS inspection",
        True,
        ("-v",),
    ),
}


def get_adapter(key: str) -> BasicLookupAdapter:
    try:
        return ADAPTERS[key]
    except KeyError as exc:
        raise KeyError(f"unknown adapter: {key}") from exc


def create_basic_lookup_request(
    tool_key: str,
    target: str,
    *,
    authorization_state: str,
    case_id: str | None = None,
    timeout_seconds: float = 120,
) -> ActionRequest:
    """Create one immutable passive-lookup request; no process is started."""
    adapter = get_adapter(tool_key)
    normalized = adapter.validate_target(target)
    return ActionRequest.create(
        adapter_key=adapter.key,
        target=normalized,
        scope=ActionScope("passive_lookup", normalized),
        authorization_state=authorization_state,
        timeout_seconds=timeout_seconds,
        case_id=case_id,
    )


def inventory() -> list[tuple[ToolSpec, bool]]:
    return [(spec, shutil.which(spec.command) is not None) for spec in TOOLS]


def run(
    spec: ToolSpec,
    args: list[str],
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [spec.command, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,
    )
