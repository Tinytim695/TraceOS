#!/usr/bin/env python3
"""TraceOS Investigation Centre subprocess/tool metadata helpers."""
from __future__ import annotations

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
