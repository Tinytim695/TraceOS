#!/usr/bin/env python3
"""TraceOS CyberLab host assessment and fail-closed isolation policy.

This foundation is deliberately read-only: it detects host capabilities and
validates a proposed isolation policy. It does not create VMs, configure host
networking, or execute guest code.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

GIB = 1024 ** 3
DEFAULT_STORAGE = Path.home() / ".local" / "share" / "traceos" / "cyberlab"
_NETWORK_MODES = frozenset({"none", "private_internal"})
_SEGMENT_PATTERN = re.compile(r"cyberlab-[0-9a-f]{8,16}\Z")


@dataclass(frozen=True, slots=True)
class HostCapabilities:
    """Read-only snapshot of resources relevant to a CyberLab host."""

    operating_mode: str
    architecture: str
    cpu_cores: int
    total_ram_bytes: int
    available_ram_bytes: int
    free_storage_bytes: int
    storage_path: str
    qemu_binary: str | None
    qemu_version: str | None
    kvm_device_present: bool
    kvm_accessible: bool
    cpu_virtualization: bool
    resource_profile: str
    warnings: tuple[str, ...]

    @property
    def hardware_acceleration_available(self) -> bool:
        return self.kvm_device_present and self.kvm_accessible

    @property
    def qemu_available(self) -> bool:
        return self.qemu_binary is not None

    @property
    def host_meets_minimum_resources(self) -> bool:
        return (
            self.total_ram_bytes >= 4 * GIB
            and self.cpu_cores >= 2
            and self.free_storage_bytes >= 12 * GIB
        )

    @property
    def prerequisites_present(self) -> bool:
        """Whether basic host prerequisites exist, not whether a lab can launch."""
        return self.qemu_available and self.host_meets_minimum_resources


@dataclass(frozen=True, slots=True)
class LabIsolationPolicy:
    """Declarative safety requirements for a future VM launch request.

    Defaults are intentionally restrictive. A snapshot must already exist
    before a launch can be approved.
    """

    network_mode: str = "none"
    external_uplink: bool = False
    nat_enabled: bool = False
    bridged_network: bool = False
    host_port_forwarding: bool = False
    shared_host_paths: bool = False
    clipboard_sharing: bool = False
    usb_passthrough: bool = False
    host_device_passthrough: bool = False
    snapshot_required: bool = True
    snapshot_present: bool = False
    network_owner: str | None = None
    network_id: str | None = None


@dataclass(frozen=True, slots=True)
class IsolationAssessment:
    allowed: bool
    findings: tuple[str, ...]


def parse_meminfo(text: str) -> tuple[int, int]:
    """Return (MemTotal, MemAvailable) in bytes; fail closed on bad input."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(MemTotal|MemAvailable|MemFree):\s+(\d+)\s+kB\s*$", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    if total < 0 or available < 0 or available > total:
        return 0, 0
    return total, available


def parse_cpu_virtualization(text: str, architecture: str) -> bool:
    """Detect advertised CPU virtualization flags without assuming they are usable."""
    flags: set[str] = set()
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in {"flags", "features"}:
            flags.update(value.lower().split())
    machine = architecture.lower()
    if machine in {"x86_64", "amd64", "i386", "i686"}:
        return bool(flags.intersection({"vmx", "svm"}))
    if machine in {"aarch64", "arm64"}:
        return "virt" in flags
    return False


def classify_resource_profile(
    total_ram_bytes: int,
    cpu_cores: int,
    free_storage_bytes: int,
) -> str:
    """Return a conservative hardware tier; values are planning guidance."""
    if total_ram_bytes >= 32 * GIB and cpu_cores >= 8 and free_storage_bytes >= 100 * GIB:
        return "full"
    if total_ram_bytes >= 16 * GIB and cpu_cores >= 6 and free_storage_bytes >= 60 * GIB:
        return "standard"
    if total_ram_bytes >= 8 * GIB and cpu_cores >= 4 and free_storage_bytes >= 30 * GIB:
        return "portable"
    if total_ram_bytes >= 4 * GIB and cpu_cores >= 2 and free_storage_bytes >= 12 * GIB:
        return "lightweight"
    return "limited"


def evaluate_isolation(policy: LabIsolationPolicy) -> IsolationAssessment:
    """Fail closed unless the proposed VM settings meet the lab policy."""
    findings: list[str] = []

    if policy.network_mode not in _NETWORK_MODES:
        findings.append("Unsupported network mode.")
    if policy.external_uplink:
        findings.append("External uplink is prohibited.")
    if policy.nat_enabled:
        findings.append("NAT is prohibited.")
    if policy.bridged_network:
        findings.append("Bridged networking is prohibited.")
    if policy.host_port_forwarding:
        findings.append("Host port forwarding is prohibited.")
    if policy.shared_host_paths:
        findings.append("Shared host folders are prohibited.")
    if policy.clipboard_sharing:
        findings.append("Clipboard sharing is prohibited.")
    if policy.usb_passthrough:
        findings.append("USB passthrough is prohibited.")
    if policy.host_device_passthrough:
        findings.append("Host device passthrough is prohibited.")
    if policy.snapshot_required and not policy.snapshot_present:
        findings.append("A clean rollback snapshot is required before launch.")

    if policy.network_mode == "none":
        if policy.network_owner is not None or policy.network_id is not None:
            findings.append("A network-free VM must not reference a virtual network.")
    elif policy.network_mode == "private_internal":
        if policy.network_owner != "cyberlab":
            findings.append("Private networks must be owned by CyberLab.")
        if not policy.network_id or not _SEGMENT_PATTERN.fullmatch(policy.network_id):
            findings.append("Private network ID is missing or invalid.")

    return IsolationAssessment(allowed=not findings, findings=tuple(findings))


def qemu_no_network_args() -> list[str]:
    """Return the only network argument currently approved for VM launch."""
    return ["-nic", "none"]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _existing_parent(path: Path) -> Path:
    current = path.expanduser()
    while not current.exists() and current != current.parent:
        current = current.parent
    return current if current.is_dir() else Path.home()


def _qemu_command(architecture: str) -> str:
    machine = architecture.lower()
    if machine in {"aarch64", "arm64"}:
        return "qemu-system-aarch64"
    if machine in {"riscv64"}:
        return "qemu-system-riscv64"
    return "qemu-system-x86_64"


def detect_host_capabilities(
    storage_path: str | Path | None = None,
) -> HostCapabilities:
    """Inspect hardware and installed QEMU without changing host state."""
    architecture = platform.machine() or "unknown"
    cpu_cores = os.cpu_count() or 0
    total_ram, available_ram = parse_meminfo(_read_text(Path("/proc/meminfo")))
    cpu_virtualization = parse_cpu_virtualization(
        _read_text(Path("/proc/cpuinfo")), architecture
    )

    live_markers = (
        Path("/run/live/medium"),
        Path("/lib/live/mount/medium"),
    )
    operating_mode = "live_usb" if any(path.exists() for path in live_markers) else "installed"

    kvm_path = Path("/dev/kvm")
    try:
        kvm_stat = kvm_path.stat()
        kvm_device_present = stat.S_ISCHR(kvm_stat.st_mode)
    except OSError:
        kvm_device_present = False
    kvm_accessible = (
        kvm_device_present and os.access(kvm_path, os.R_OK | os.W_OK)
    )

    configured_storage = Path(storage_path).expanduser() if storage_path else Path(
        os.environ.get("TRACEOS_CYBERLAB_STORAGE", str(DEFAULT_STORAGE))
    ).expanduser()
    storage_probe = _existing_parent(configured_storage)
    try:
        free_storage = shutil.disk_usage(storage_probe).free
    except OSError:
        free_storage = 0

    command = _qemu_command(architecture)
    qemu_binary = shutil.which(command)
    qemu_version: str | None = None
    warnings: list[str] = []

    if qemu_binary:
        try:
            result = subprocess.run(
                [qemu_binary, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
                shell=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                qemu_version = result.stdout.strip().splitlines()[0][:200]
            else:
                warnings.append("QEMU was found but its version could not be read.")
        except (OSError, subprocess.SubprocessError):
            warnings.append("QEMU was found but its version check failed.")
    else:
        warnings.append(f"{command} is not installed.")

    if not kvm_device_present:
        warnings.append("/dev/kvm is unavailable; hardware acceleration is not available.")
    elif not kvm_accessible:
        warnings.append("/dev/kvm exists but is not accessible to this user.")
    if not cpu_virtualization:
        warnings.append("CPU virtualization flags were not detected.")
    if total_ram < 4 * GIB:
        warnings.append("Less than 4 GiB RAM detected; VM experiments are not recommended.")
    if free_storage < 12 * GIB:
        warnings.append("Less than 12 GiB free storage at the configured lab path.")

    profile = classify_resource_profile(total_ram, cpu_cores, free_storage)
    return HostCapabilities(
        operating_mode=operating_mode,
        architecture=architecture,
        cpu_cores=cpu_cores,
        total_ram_bytes=total_ram,
        available_ram_bytes=available_ram,
        free_storage_bytes=free_storage,
        storage_path=str(configured_storage),
        qemu_binary=qemu_binary,
        qemu_version=qemu_version,
        kvm_device_present=kvm_device_present,
        kvm_accessible=kvm_accessible,
        cpu_virtualization=cpu_virtualization,
        resource_profile=profile,
        warnings=tuple(warnings),
    )


def format_capability_report(report: HostCapabilities) -> str:
    """Format a stable, human-readable status report for the Control Centre."""
    def gib(value: int) -> str:
        return f"{value / GIB:.1f} GiB"

    qemu = report.qemu_version or report.qemu_binary or "Not installed"
    kvm = "Available" if report.hardware_acceleration_available else "Unavailable"
    cpu_virt = "Detected" if report.cpu_virtualization else "Not detected"
    lines = [
        "TRACEOS CYBERLAB — HOST READINESS",
        "=" * 42,
        f"Operating mode:       {report.operating_mode.replace('_', ' ').title()}",
        f"Architecture:         {report.architecture}",
        f"CPU cores:            {report.cpu_cores}",
        f"Memory:               {gib(report.available_ram_bytes)} available / {gib(report.total_ram_bytes)} total",
        f"Lab storage free:     {gib(report.free_storage_bytes)}",
        f"Storage path:         {report.storage_path}",
        f"QEMU:                 {qemu}",
        f"CPU virtualization:   {cpu_virt}",
        f"KVM acceleration:    {kvm}",
        f"Resource profile:     {report.resource_profile.upper()}",
        f"Basic prerequisites:  {'PRESENT' if report.prerequisites_present else 'INCOMPLETE'}",
        "",
        "SAFETY BASELINE",
        "- No VM is created by this page.",
        "- No host network settings are modified.",
        "- VM launch remains disabled until the isolated backend is implemented.",
        "- Network-free QEMU profile: -nic none",
        "- Private lab networking must never have NAT, bridging or host forwarding.",
        "- Every experiment must start from a clean rollback snapshot.",
    ]
    if report.warnings:
        lines.extend(["", "WARNINGS"])
        lines.extend(f"- {warning}" for warning in report.warnings)
    return "\n".join(lines)
