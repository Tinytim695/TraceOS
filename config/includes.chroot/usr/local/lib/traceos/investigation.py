#!/usr/bin/env python3
"""TraceOS Investigation Centre subprocess/tool metadata helpers."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass


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


def inventory() -> list[tuple[ToolSpec, bool]]:
    return [(spec, shutil.which(spec.command) is not None) for spec in TOOLS]


def run(spec: ToolSpec, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [spec.command, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        shell=False,
    )
