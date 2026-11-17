#!/usr/bin/env python3
"""TraceOS CyberLab host assessment, isolation policy and offline clones.

Host detection and policy checks are read-only. Storage preparation and clone
import are explicit operations: they copy a local website or application tree
into a private directory. They do not fetch URLs, execute guest code, create
VMs, or change host networking.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

GIB = 1024 ** 3
DEFAULT_STORAGE = Path.home() / ".local" / "share" / "traceos" / "cyberlab"
_NETWORK_MODES = frozenset({"none", "private_internal"})
_SEGMENT_PATTERN = re.compile(r"cyberlab-[0-9a-f]{8,16}\Z")
_SANDBOX_ID_PATTERN = re.compile(r"sandbox-[0-9a-f]{8}\Z")
_NAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
STORAGE_CHILDREN = ("golden", "overlays", "evidence", "sandboxes")
_CLONE_KINDS = frozenset({"website", "app"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_BIND_HOST = "127.0.0.1"
MAX_CLONE_FILES = 4000
MAX_CLONE_BYTES = 256 * 1024 * 1024
_FORBIDDEN_STORAGE_ROOTS = frozenset({
    "/",
    "/home",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var",
    "/tmp",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/boot",
    "/opt",
    "/root",
    "/media",
    "/mnt",
    "/srv",
})


class CyberLabError(Exception):
    """Fail-closed CyberLab error. Callers must not continue the operation."""


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
    host_route: bool = False
    dns_forwarding: bool = False
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


@dataclass(frozen=True, slots=True)
class StorageStatus:
    """Read-only view of the CyberLab directory layout."""

    path: str
    prepared: bool
    findings: tuple[str, ...]
    sandbox_count: int


@dataclass(frozen=True, slots=True)
class SandboxManifest:
    """Metadata for one offline website or application clone."""

    sandbox_id: str
    kind: str
    name: str
    path: str
    origin_label: str
    content_sha256: str
    file_count: int
    byte_count: int
    bind_host: str
    execution: str


@dataclass(frozen=True, slots=True)
class SandboxInventory:
    manifests: tuple[SandboxManifest, ...]
    warnings: tuple[str, ...]


@dataclass
class LoopbackCloneServer:
    """Local server bound only to 127.0.0.1. It never dials the recorded origin."""

    manifest: SandboxManifest
    httpd: ThreadingHTTPServer
    thread: threading.Thread

    @property
    def url(self) -> str:
        port = int(self.httpd.server_address[1])
        return f"http://127.0.0.1:{port}/"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=3)


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
    if policy.host_route:
        findings.append("Routes from the lab to the host or host LAN are prohibited.")
    if policy.dns_forwarding:
        findings.append("DNS forwarding outside the private lab is prohibited.")
    if policy.shared_host_paths:
        findings.append("Shared host folders are prohibited.")
    if policy.clipboard_sharing:
        findings.append("Clipboard sharing is prohibited.")
    if policy.usb_passthrough:
        findings.append("USB passthrough is prohibited.")
    if policy.host_device_passthrough:
        findings.append("Host device passthrough is prohibited.")
    if not policy.snapshot_required:
        findings.append("The clean rollback snapshot requirement cannot be disabled.")
    elif not policy.snapshot_present:
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


def configured_storage_path(storage_path: str | Path | None = None) -> Path:
    """Return the configured storage root without creating it."""
    if storage_path is None:
        raw = os.environ.get("TRACEOS_CYBERLAB_STORAGE", str(DEFAULT_STORAGE))
    else:
        raw = str(storage_path)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise CyberLabError("CyberLab storage path must be absolute.")
    if ".." in path.parts:
        raise CyberLabError("CyberLab storage path must not contain '..'.")
    if len(path.as_posix()) > 4096:
        raise CyberLabError("CyberLab storage path is too long.")
    return path


def inspect_storage(storage_path: str | Path | None = None) -> StorageStatus:
    """Report whether the lab layout exists and is private. Does not create it."""
    root = configured_storage_path(storage_path)
    findings: list[str] = []
    try:
        _assert_storage_root_allowed(root)
    except CyberLabError as exc:
        return StorageStatus(str(root), False, (str(exc),), 0)

    if not root.exists():
        return StorageStatus(
            str(root),
            False,
            ("CyberLab storage has not been prepared.",),
            0,
        )
    try:
        _assert_private_dir(root, label="CyberLab storage")
    except CyberLabError as exc:
        return StorageStatus(str(root), False, (str(exc),), 0)

    sandbox_count = 0
    for name in STORAGE_CHILDREN:
        child = root / name
        if child.is_symlink() or not child.is_dir():
            findings.append(f"Storage child {name} is missing or not a real directory.")
            continue
        try:
            _assert_private_dir(child, label=f"Storage child {name}")
        except CyberLabError as exc:
            findings.append(str(exc))
        if name == "sandboxes":
            try:
                sandbox_count = sum(
                    1
                    for entry in child.iterdir()
                    if _SANDBOX_ID_PATTERN.fullmatch(entry.name) and not entry.is_symlink()
                )
            except OSError:
                findings.append("Sandbox directory could not be read.")
    return StorageStatus(str(root), not findings, tuple(findings), sandbox_count)


def prepare_storage(storage_path: str | Path | None = None) -> StorageStatus:
    """Create the private lab directories. Never mounts, formats or contacts a network."""
    root = configured_storage_path(storage_path)
    _assert_storage_root_allowed(root)
    if root.is_symlink():
        raise CyberLabError("Refusing to prepare a symlinked storage path.")
    if root.exists():
        _assert_private_dir(root, label="CyberLab storage")
    else:
        parent = root.parent
        if parent.is_symlink() or not parent.is_dir():
            raise CyberLabError("CyberLab storage parent is missing or not a real directory.")
        _reject_symlink_ancestors(parent)
        if not os.access(parent, os.W_OK | os.X_OK):
            raise CyberLabError("CyberLab storage parent is not writable by the current user.")
        os.mkdir(root, 0o700)
        os.chmod(root, 0o700)
        _assert_private_dir(root, label="CyberLab storage")

    for name in STORAGE_CHILDREN:
        child = root / name
        if child.is_symlink():
            raise CyberLabError(f"Refusing symlinked storage child: {name}.")
        if child.exists():
            _assert_private_dir(child, label=f"Storage child {name}")
            continue
        os.mkdir(child, 0o700)
        os.chmod(child, 0o700)
        _assert_private_dir(child, label=f"Storage child {name}")
    status = inspect_storage(root)
    if not status.prepared:
        raise CyberLabError(status.findings[0] if status.findings else "Storage preparation failed.")
    return status


def import_local_clone(
    source: str | Path,
    *,
    kind: str,
    name: str,
    origin_label: str = "",
    storage_path: str | Path | None = None,
) -> SandboxManifest:
    """Copy a local website or app tree into an offline sandbox.

    The source must already be on disk. This function does not resolve DNS,
    open a socket, fetch a URL, or execute anything inside the tree.
    """
    if kind not in _CLONE_KINDS:
        raise CyberLabError("Clone kind must be website or app.")
    safe_name = _validate_clone_name(name)
    safe_origin = _validate_origin_label(origin_label)
    status = inspect_storage(storage_path)
    if not status.prepared:
        detail = status.findings[0] if status.findings else "CyberLab storage is not prepared."
        raise CyberLabError(detail)

    source_path = Path(source).expanduser()
    if not source_path.is_absolute():
        raise CyberLabError("Clone source must be an absolute path.")
    if source_path.is_symlink():
        raise CyberLabError("Refusing a symlinked clone source.")
    _reject_symlink_ancestors(source_path)
    if not source_path.is_dir():
        raise CyberLabError("Clone source must be a real directory.")

    root = configured_storage_path(storage_path)
    source_real = source_path.resolve(strict=True)
    storage_real = root.resolve(strict=True)
    if (
        source_real == storage_real
        or storage_real in source_real.parents
        or source_real in storage_real.parents
    ):
        raise CyberLabError("Refusing to clone the CyberLab storage tree into itself.")

    files = _collect_clone_files(source_path)
    sandbox_id = "sandbox-" + secrets.token_hex(4)
    sandbox_dir = root / "sandboxes" / sandbox_id
    content_dir = sandbox_dir / "content"
    copied: list[tuple[str, str, int]] = []
    try:
        os.mkdir(sandbox_dir, 0o700)
        os.chmod(sandbox_dir, 0o700)
        os.mkdir(content_dir, 0o700)
        os.chmod(content_dir, 0o700)
        used = 0
        for src, rel in files:
            dest = content_dir.joinpath(*rel.parts)
            size, digest = _copy_regular_file(src, dest, content_dir)
            used += size
            if used > MAX_CLONE_BYTES:
                raise CyberLabError("Clone exceeds the size limit.")
            copied.append((rel.as_posix(), digest, size))
        tree_hash = hashlib.sha256()
        for rel, digest, _size in copied:
            tree_hash.update(rel.encode("utf-8"))
            tree_hash.update(b"\0")
            tree_hash.update(digest.encode("ascii"))
            tree_hash.update(b"\0")
        manifest = SandboxManifest(
            sandbox_id=sandbox_id,
            kind=kind,
            name=safe_name,
            path=str(sandbox_dir),
            origin_label=safe_origin,
            content_sha256=tree_hash.hexdigest(),
            file_count=len(copied),
            byte_count=used,
            bind_host=_BIND_HOST,
            execution="stored_only",
        )
        _write_manifest(sandbox_dir / "manifest.json", manifest)
        return manifest
    except BaseException:
        _remove_sandbox_dir(sandbox_dir)
        raise


def list_sandboxes(storage_path: str | Path | None = None) -> SandboxInventory:
    """Read sandbox manifests. Invalid entries are ignored, not executed."""
    status = inspect_storage(storage_path)
    if not status.prepared and not (Path(status.path) / "sandboxes").is_dir():
        return SandboxInventory((), status.findings)
    sandboxes = Path(status.path) / "sandboxes"
    manifests: list[SandboxManifest] = []
    warnings: list[str] = []
    try:
        entries = sorted(sandboxes.iterdir(), key=lambda item: item.name)
    except OSError:
        return SandboxInventory((), ("Sandbox directory could not be read.",))
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir():
            warnings.append("Ignoring a non-directory sandbox entry.")
            continue
        if not _SANDBOX_ID_PATTERN.fullmatch(entry.name):
            warnings.append("Ignoring a sandbox directory with an invalid id.")
            continue
        try:
            manifests.append(_read_manifest(entry))
        except CyberLabError:
            warnings.append(f"Ignoring invalid manifest for {entry.name}.")
    return SandboxInventory(tuple(manifests), tuple(warnings))


def origin_hostname(label: str) -> str | None:
    """Extract a display hostname. This never performs a lookup."""
    text = label.strip()
    if not text:
        return None
    if "://" in text:
        host = urlsplit(text).hostname
    else:
        host = text.split("/")[0]
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]
        else:
            host = host.split(":")[0]
    if not host:
        return None
    return host.lower().rstrip(".")


def evaluate_test_target(manifest: SandboxManifest, host: str) -> IsolationAssessment:
    """Allow a test target only when it is loopback and not the recorded origin."""
    findings: list[str] = []
    candidate = host.strip().lower()
    if (
        not candidate
        or any(ord(char) < 33 or ord(char) == 127 for char in candidate)
        or "/" in candidate
        or "@" in candidate
        or "\\" in candidate
    ):
        findings.append("Test target host is missing or invalid.")
    elif candidate not in _LOOPBACK_HOSTS:
        findings.append("Tests may target loopback only.")

    origin = origin_hostname(manifest.origin_label)
    if origin and (candidate == origin or candidate.endswith("." + origin)):
        findings.append("Tests must not contact the recorded origin.")
    if manifest.bind_host != _BIND_HOST or manifest.execution != "stored_only":
        findings.append("Sandbox is not an offline stored clone.")
    # Deduplicate while preserving order.
    unique: list[str] = []
    for finding in findings:
        if finding not in unique:
            unique.append(finding)
    return IsolationAssessment(allowed=not unique, findings=tuple(unique))


def assert_loopback_bind(host: str) -> None:
    """Reject every bind address except the IPv4 loopback address."""
    if host != _BIND_HOST:
        raise CyberLabError("Clone servers must bind 127.0.0.1 only.")


def serve_clone_loopback(manifest: SandboxManifest, port: int = 0) -> LoopbackCloneServer:
    """Serve clone files on 127.0.0.1. Does not connect to the recorded origin."""
    if manifest.execution != "stored_only" or manifest.bind_host != _BIND_HOST:
        raise CyberLabError("Refusing to serve a sandbox that is not stored offline.")
    if not isinstance(port, int) or port < 0 or port > 65535:
        raise CyberLabError("Invalid loopback port.")
    content_root = Path(manifest.path) / "content"
    if content_root.is_symlink() or not content_root.is_dir():
        raise CyberLabError("Sandbox content directory is missing.")
    assert_loopback_bind(_BIND_HOST)
    httpd = _CloneHTTPServer((_BIND_HOST, port), _CloneRequestHandler)
    bound_host = httpd.socket.getsockname()[0]
    if bound_host != _BIND_HOST:
        httpd.server_close()
        raise CyberLabError("Clone server failed to bind loopback.")
    httpd.content_root = content_root.resolve()
    httpd.sandbox_id = manifest.sandbox_id
    thread = threading.Thread(
        target=httpd.serve_forever,
        name=f"cyberlab-{manifest.sandbox_id}",
        daemon=True,
    )
    thread.start()
    return LoopbackCloneServer(manifest=manifest, httpd=httpd, thread=thread)


def format_sandbox_report(status: StorageStatus, inventory: SandboxInventory) -> str:
    """Format offline-clone status without creating directories or listeners."""
    prepared = "YES" if status.prepared else "NO"
    lines = [
        "TRACEOS CYBERLAB — OFFLINE CLONE SANDBOX",
        "=" * 44,
        f"Storage:              {status.path}",
        f"Prepared:             {prepared}",
        f"Sandbox count:        {status.sandbox_count}",
        "",
        "POLICY",
        "- Clones are copied only from a local folder. URLs are not fetched.",
        "- Website and application trees are stored and are not executed.",
        "- A loopback server, when started explicitly, binds 127.0.0.1 only.",
        "- Tests must not contact the recorded origin.",
        "- This report does not prepare storage, import a clone, or open a socket.",
        "- No VM is started and no host network settings are modified.",
    ]
    if inventory.manifests:
        lines.extend(["", "SANDBOXES"])
        for manifest in inventory.manifests:
            origin = manifest.origin_label or "not recorded"
            lines.append(
                f"- {manifest.sandbox_id}  {manifest.kind}  {manifest.name}  "
                f"files={manifest.file_count}  origin={origin}  served=no"
            )
    if status.findings or inventory.warnings:
        lines.extend(["", "NOTES"])
        lines.extend(f"- {note}" for note in (*status.findings, *inventory.warnings))
    return "\n".join(lines)


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

    configured_storage = configured_storage_path(storage_path)
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


def _assert_storage_root_allowed(path: Path) -> None:
    normalized = path.as_posix().rstrip("/") or "/"
    if normalized in _FORBIDDEN_STORAGE_ROOTS:
        raise CyberLabError("Refusing to use a system directory as CyberLab storage.")
    if path == Path.home():
        raise CyberLabError("Refusing to use the home directory itself as CyberLab storage.")


def _reject_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    relative = path.relative_to(current) if path.is_absolute() else path
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise CyberLabError("Refusing a symlink in the CyberLab path.")
        if current == path:
            break
        if not current.exists():
            break


def _assert_private_dir(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise CyberLabError(f"{label} must not be a symlink.")
    try:
        info = path.lstat()
    except OSError as exc:
        raise CyberLabError(f"{label} could not be inspected.") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise CyberLabError(f"{label} must be a real directory.")
    if info.st_uid != os.getuid():
        raise CyberLabError(f"{label} must be owned by the current user.")
    if info.st_mode & 0o077:
        raise CyberLabError(f"{label} must not be group or world accessible.")


def _validate_clone_name(name: str) -> str:
    cleaned = name.strip().lower()
    if not _NAME_PATTERN.fullmatch(cleaned):
        raise CyberLabError(
            "Sandbox name must be 1-40 lowercase letters, numbers and hyphens."
        )
    return cleaned


def _validate_origin_label(label: str) -> str:
    text = label.strip()
    if len(text) > 200:
        raise CyberLabError("Origin label is too long.")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise CyberLabError("Origin label contains control characters.")
    return text


def _collect_clone_files(source: Path) -> list[tuple[Path, Path]]:
    collected: list[tuple[Path, Path]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        current = Path(dirpath)
        if current.is_symlink():
            raise CyberLabError("Refusing a symlink inside the clone source.")
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            child = current / dirname
            if child.is_symlink():
                raise CyberLabError("Refusing a symlink inside the clone source.")
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in sorted(filenames):
            candidate = current / filename
            if candidate.is_symlink():
                raise CyberLabError("Refusing a symlink inside the clone source.")
            info = candidate.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise CyberLabError("Refusing a non-regular file inside the clone source.")
            rel = candidate.relative_to(source)
            if rel.is_absolute() or ".." in rel.parts:
                raise CyberLabError("Clone path escaped the source directory.")
            total += info.st_size
            if info.st_size > MAX_CLONE_BYTES or total > MAX_CLONE_BYTES:
                raise CyberLabError("Clone exceeds the size limit.")
            collected.append((candidate, rel))
            if len(collected) > MAX_CLONE_FILES:
                raise CyberLabError("Clone exceeds the file limit.")
    if not collected:
        raise CyberLabError("Clone source has no files.")
    return collected


def _copy_regular_file(src: Path, dest: Path, content_dir: Path) -> tuple[int, str]:
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = dest.parent
    while True:
        if current != content_dir and content_dir not in current.parents:
            raise CyberLabError("Clone destination escaped the sandbox.")
        os.chmod(current, 0o700)
        if current == content_dir:
            break
        current = current.parent
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(dest, flags, 0o600)
    hasher = hashlib.sha256()
    total = 0
    try:
        with open(src, "rb") as infile, os.fdopen(descriptor, "wb") as outfile:
            descriptor = -1
            while True:
                chunk = infile.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_CLONE_BYTES:
                    raise CyberLabError("Clone exceeds the size limit.")
                hasher.update(chunk)
                outfile.write(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(dest, 0o600)
    return total, hasher.hexdigest()


def _manifest_payload(manifest: SandboxManifest) -> dict[str, object]:
    return {
        "schema": 1,
        "sandbox_id": manifest.sandbox_id,
        "kind": manifest.kind,
        "name": manifest.name,
        "origin_label": manifest.origin_label,
        "content_sha256": manifest.content_sha256,
        "file_count": manifest.file_count,
        "byte_count": manifest.byte_count,
        "bind_host": manifest.bind_host,
        "execution": manifest.execution,
        "network": {
            "mode": "loopback_only",
            "origin_contact": "prohibited",
        },
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _write_manifest(path: Path, manifest: SandboxManifest) -> None:
    payload = json.dumps(_manifest_payload(manifest), indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(path, 0o600)


def _read_manifest(sandbox_dir: Path) -> SandboxManifest:
    manifest_path = sandbox_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CyberLabError("Sandbox manifest is missing.")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CyberLabError("Sandbox manifest is unreadable.") from exc
    if not isinstance(payload, dict):
        raise CyberLabError("Sandbox manifest is invalid.")
    sandbox_id = payload.get("sandbox_id")
    kind = payload.get("kind")
    name = payload.get("name")
    origin_label = payload.get("origin_label", "")
    content_sha256 = payload.get("content_sha256")
    file_count = payload.get("file_count")
    byte_count = payload.get("byte_count")
    bind_host = payload.get("bind_host")
    execution = payload.get("execution")
    network = payload.get("network")
    if (
        not isinstance(sandbox_id, str)
        or sandbox_id != sandbox_dir.name
        or not _SANDBOX_ID_PATTERN.fullmatch(sandbox_id)
        or kind not in _CLONE_KINDS
        or not isinstance(name, str)
        or not _NAME_PATTERN.fullmatch(name)
        or not isinstance(origin_label, str)
        or not isinstance(content_sha256, str)
        or not _SHA256_PATTERN.fullmatch(content_sha256)
        or not isinstance(file_count, int)
        or not isinstance(byte_count, int)
        or file_count < 1
        or byte_count < 0
        or bind_host != _BIND_HOST
        or execution != "stored_only"
        or not isinstance(network, dict)
        or network.get("mode") != "loopback_only"
        or network.get("origin_contact") != "prohibited"
    ):
        raise CyberLabError("Sandbox manifest is invalid.")
    return SandboxManifest(
        sandbox_id=sandbox_id,
        kind=kind,
        name=name,
        path=str(sandbox_dir),
        origin_label=origin_label,
        content_sha256=content_sha256,
        file_count=file_count,
        byte_count=byte_count,
        bind_host=bind_host,
        execution=execution,
    )


def _remove_sandbox_dir(sandbox_dir: Path) -> None:
    parent = sandbox_dir.parent
    if parent.name != "sandboxes" or not _SANDBOX_ID_PATTERN.fullmatch(sandbox_dir.name):
        return
    if sandbox_dir.is_symlink() or not sandbox_dir.exists():
        return
    shutil.rmtree(sandbox_dir)


class _CloneHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    content_root: Path
    sandbox_id: str

    def server_bind(self) -> None:
        host = self.server_address[0]
        assert_loopback_bind(str(host))
        super().server_bind()


class _CloneRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._serve(send_body=True)

    def do_HEAD(self) -> None:
        self._serve(send_body=False)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _serve(self, *, send_body: bool) -> None:
        content_root = getattr(self.server, "content_root", None)
        sandbox_id = getattr(self.server, "sandbox_id", "")
        if not isinstance(content_root, Path):
            self.send_error(500)
            return
        relative = _safe_content_relative(self.path)
        if relative is None:
            self.send_error(400)
            return
        candidate = content_root.joinpath(*relative.parts) if relative.parts else content_root / "index.html"
        try:
            candidate.relative_to(content_root)
        except ValueError:
            self.send_error(400)
            return
        if candidate.is_symlink() or not candidate.is_file():
            self.send_error(404)
            return
        try:
            data = candidate.read_bytes()
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-TraceOS-Sandbox", str(sandbox_id))
        self.end_headers()
        if send_body:
            self.wfile.write(data)


def _safe_content_relative(url_path: str) -> Path | None:
    raw_path = urlsplit(url_path).path
    if raw_path in {"", "/"}:
        return Path("index.html")
    decoded = unquote(raw_path)
    if "\x00" in decoded or "\\" in decoded or decoded.startswith("//"):
        return None
    relative = Path(decoded.lstrip("/"))
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    return relative
