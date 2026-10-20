#!/usr/bin/env python3
"""Select and verify TraceOS wallpaper targets after XFCE has settled."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import quote

WALLPAPER = Path("/usr/share/backgrounds/traceos/traceos-wallpaper.png")
STATE_RELATIVE = Path(".config/traceos/desktop-branding-initialized")
STATE_VERSION = "traceos-desktop-branding-v2"
READY_ATTEMPTS = 30
STABLE_SAMPLES = 3
POLL_SECONDS = 1.0

MONITOR_ROW = re.compile(r"^\s*(\d+):\s+(.+?)\s*$")
OUTPUT_CONNECTED = re.compile(r"^\s*(\S+)\s+connected\b")
BACKDROP_IMAGE = re.compile(
    r"^/backdrop/screen(?P<screen>\d+)/monitor(?P<monitor>[^/]+)/"
    r"workspace(?P<workspace>\d+)/last-image$"
)
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
Logger = Callable[[str], None]


@dataclass(frozen=True)
class ActiveMonitor:
    index: int
    name: str


@dataclass(frozen=True)
class WallpaperTarget:
    output: str
    last_image: str
    mode: str = "existing-exact-output-name"

    @property
    def image_style(self) -> str:
        return self.last_image.removesuffix("last-image") + "image-style"


def system_runner(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(list(args), capture_output=True, text=True, check=False, timeout=4)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(args), 127, "", str(exc))


def _call(runner: Runner, args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return runner(args)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(args), 127, "", str(exc))


def parse_active_monitors(listmonitors_text: str, query_text: str) -> tuple[ActiveMonitor, ...]:
    connected = {
        match.group(1)
        for line in query_text.splitlines()
        if (match := OUTPUT_CONNECTED.match(line)) is not None
    }
    monitors: list[ActiveMonitor] = []
    for line in listmonitors_text.splitlines():
        match = MONITOR_ROW.match(line)
        if not match:
            continue
        fields = match.group(2).split()
        if not fields:
            continue
        name = fields[-1]
        if name in connected:
            monitors.append(ActiveMonitor(int(match.group(1)), name))
    return tuple(monitors)


def parse_property_dump(dump: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in dump.splitlines():
        path, separator, value = line.strip().partition(" ")
        if separator and path.startswith("/"):
            properties[path] = value.strip()
    return properties


def discover_wallpaper_targets(
    monitors: Sequence[ActiveMonitor], properties: dict[str, str]
) -> tuple[tuple[WallpaperTarget, ...], tuple[str, ...]]:
    """Resolve targets by the XRandR output name, not a guessed numeric index.

    XFCE's skeleton may contain monitor0 before the live session has created
    monitorVirtual-1. Treating those as interchangeable can make xfconf-query
    read back successfully while xfdesktop continues painting the other image.
    When the named target has not appeared yet, create the exact output-name
    property for the known workspaces and verify it later by readback.
    """
    parsed: list[tuple[str, int, str, int]] = []
    for path in properties:
        match = BACKDROP_IMAGE.match(path)
        if match:
            parsed.append((path, int(match.group("screen")), match.group("monitor"),
                           int(match.group("workspace"))))
    targets: list[WallpaperTarget] = []
    missing: list[str] = []
    workspaces = sorted({row[3] for row in parsed if row[1] == 0}) or [0]
    for monitor in monitors:
        named = [row for row in parsed if row[1] == 0 and row[2] == monitor.name]
        if named:
            targets.extend(
                WallpaperTarget(monitor.name, row[0], "existing-exact-output-name")
                for row in sorted(named, key=lambda item: item[3])
            )
            continue
        targets.extend(
            WallpaperTarget(
                monitor.name,
                f"/backdrop/screen0/monitor{monitor.name}/workspace{workspace}/last-image",
                "created-exact-output-name",
            )
            for workspace in workspaces
        )
    return tuple(targets), tuple(missing)


def is_stock_wallpaper(path: str) -> bool:
    value = path.strip()
    return (
        value.startswith("/usr/share/backgrounds/xfce/")
        or value.startswith("/usr/share/backgrounds/xfce4/")
        or value.startswith("/usr/share/images/desktop-base/")
        or value.startswith("/usr/share/xfce4/wallpapers/")
        or value.endswith("/xfce-blue.jpg")
    )


def valid_image_style(value: str | None) -> bool:
    return value is not None and re.fullmatch(r"[0-5]", value.strip()) is not None


def png_details(path: Path) -> tuple[int, int, str] | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            header = handle.read(24)
            if (len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n"
                    or header[12:16] != b"IHDR"):
                return None
            width, height = struct.unpack(">II", header[16:24])
            if width <= 0 or height <= 0:
                return None
            digest.update(header)
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return width, height, digest.hexdigest()
    except OSError:
        return None


def load_branding_state(path: Path) -> tuple[str, dict[str, dict[str, str]]]:
    if not path.exists():
        return "none", {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "legacy", {}
    if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
        return "legacy", {}
    targets = data.get("targets")
    if not isinstance(targets, dict):
        return "legacy", {}
    normalized: dict[str, dict[str, str]] = {}
    for key, value in targets.items():
        if isinstance(key, str) and isinstance(value, dict):
            image, style = value.get("image"), value.get("style")
            if isinstance(image, str) and isinstance(style, str):
                normalized[key] = {"image": image, "style": style}
    return "v2", normalized


def _encode(value: str | None) -> str:
    if value is None or value == "":
        return "none"
    return quote(value, safe="/:@._-+,=")


def _emit(logger: Logger, result: str, **fields: str | int) -> None:
    suffix = " ".join(f"{key}={_encode(str(value))}" for key, value in fields.items())
    logger(f"[TraceOS] stage=TRACEOS_DESKTOP_BRANDING_RESULT result={result} {suffix}".rstrip())


def _emit_discovery(logger: Logger, result: str, **fields: str | int) -> None:
    suffix = " ".join(f"{key}={_encode(str(value))}" for key, value in fields.items())
    logger(f"[TraceOS] stage=TRACEOS_DESKTOP_BACKDROP_DISCOVERY result={result} {suffix}".rstrip())


def _emit_runtime_property(logger: Logger, kind: str, **fields: str | int) -> None:
    """Retain exact runtime output/property evidence in the setup log and QEMU serial."""
    suffix = " ".join(f"{key}={_encode(str(value))}" for key, value in fields.items())
    logger(
        f"[TraceOS] stage=TRACEOS_DESKTOP_RUNTIME_PROPERTY kind={_encode(kind)} {suffix}".rstrip()
    )


def _query(runner: Runner, channel: str, path: str) -> str | None:
    result = _call(runner, ["xfconf-query", "-c", channel, "-p", path])
    return result.stdout.strip() if result.returncode == 0 else None


def _set_verify(
    runner: Runner, path: str, value_type: str, value: str, known_paths: set[str]
) -> bool:
    args = ["xfconf-query", "-c", "xfce4-desktop", "-p", path]
    if path in known_paths:
        args.extend(["-s", value])
    else:
        args.extend(["-n", "-t", value_type, "-s", value])
    result = _call(runner, args)
    if result.returncode != 0:
        return False
    return _query(runner, "xfce4-desktop", path) == value


def setup_wallpaper(
    *,
    home: Path | None = None,
    wallpaper: Path = WALLPAPER,
    runner: Runner = system_runner,
    sleeper: Callable[[float], None] = time.sleep,
    logger: Logger = print,
    ready_attempts: int = READY_ATTEMPTS,
    stable_samples: int = STABLE_SAMPLES,
    poll_seconds: float = POLL_SECONDS,
) -> bool:
    """Brand only verified active outputs; keep incomplete runs retryable and non-fatal."""
    home = home or Path.home()
    state = home / STATE_RELATIVE
    png = png_details(wallpaper)
    if png is None:
        _emit(logger, "FAIL", reason="packaged_png_missing_or_invalid", targets=0)
        return False
    width, height, checksum = png
    previous_signature = None
    stable_count = 0
    active_outputs: tuple[ActiveMonitor, ...] = ()
    targets: tuple[WallpaperTarget, ...] = ()
    properties: dict[str, str] = {}
    theme = "unknown"
    missing: tuple[str, ...] = ()

    for _ in range(ready_attempts):
        desktop_ready = _call(runner, ["pgrep", "-x", "xfdesktop"]).returncode == 0
        listed = _call(runner, ["xrandr", "--listmonitors"])
        queried = _call(runner, ["xrandr", "--query"])
        dumped = _call(runner, ["xfconf-query", "-c", "xfce4-desktop", "-lv"])
        theme_value = _query(runner, "xsettings", "/Net/ThemeName")
        candidate_outputs = parse_active_monitors(
            listed.stdout if listed.returncode == 0 else "",
            queried.stdout if queried.returncode == 0 else "",
        )
        candidate_properties = parse_property_dump(dumped.stdout if dumped.returncode == 0 else "")
        candidate_targets, candidate_missing = discover_wallpaper_targets(
            candidate_outputs, candidate_properties
        )
        active_outputs, targets, properties, missing = (
            candidate_outputs, candidate_targets, candidate_properties, candidate_missing
        )
        theme = theme_value or "unknown"
        ready = (
            desktop_ready and bool(candidate_outputs) and bool(candidate_targets)
            and not candidate_missing and dumped.returncode == 0
            and len({target.output for target in candidate_targets}) == len(candidate_outputs)
        )
        signature = (candidate_outputs, candidate_targets, tuple(sorted(candidate_properties.items())))
        if ready and signature == previous_signature:
            stable_count += 1
        elif ready:
            previous_signature, stable_count = signature, 1
        else:
            previous_signature, stable_count = None, 0
        if stable_count >= stable_samples:
            break
        sleeper(poll_seconds)
    else:
        discovered_backdrops = sorted(path for path in properties if BACKDROP_IMAGE.match(path))
        _emit_discovery(logger, "FAIL",
              outputs=",".join(m.name for m in active_outputs) or "none",
              discovered_backdrops=",".join(discovered_backdrops) or "none",
              candidate_targets=",".join(t.last_image for t in targets) or "none",
              target_modes=",".join(t.mode for t in targets) or "none",
              missing_outputs=",".join(missing) or "none")
        _emit(logger, "FAIL", reason="runtime_targets_not_ready",
              outputs=",".join(m.name for m in active_outputs) or "none",
              missing_outputs=",".join(missing) or "none",
              backdrop_targets=",".join(t.last_image for t in targets) or "none",
              xsettings_theme=theme, targets=len(targets),
              png_width=width, png_height=height, png_sha256=checksum)
        return False

    discovered_backdrops = sorted(path for path in properties if BACKDROP_IMAGE.match(path))
    # Preserve raw runtime evidence, not just the final success marker. The
    # QEMU diagnostic bridge forwards these records into the retained serial log.
    for line in listed.stdout.splitlines():
        _emit_runtime_property(logger, "xrandr_monitor", line=line)
    for line in queried.stdout.splitlines():
        _emit_runtime_property(logger, "xrandr_query", line=line)
    for path, value in sorted(properties.items()):
        _emit_runtime_property(logger, "xfconf_property", path=path, value=value)

    _emit_discovery(logger, "READY",
          outputs=",".join(m.name for m in active_outputs) or "none",
          discovered_backdrops=",".join(discovered_backdrops) or "none",
          candidate_targets=",".join(t.last_image for t in targets) or "none",
          target_modes=",".join(t.mode for t in targets) or "none",
          missing_outputs=",".join(missing) or "none")
    state_mode, saved_targets = load_branding_state(state)
    before = {
        target.last_image: (
            properties.get(target.last_image),
            properties.get(target.image_style),
        ) for target in targets
    }
    expected: dict[str, tuple[str, str]] = {}
    force: dict[str, bool] = {}
    for target in targets:
        path = target.last_image
        current_image, current_style = before[path]
        saved = saved_targets.get(path) if state_mode == "v2" else None
        if saved:
            # A changed saved image/style is a user choice, even if it is a distro path.
            image = current_image or saved["image"]
            style = current_style if valid_image_style(current_style) else saved["style"]
            should_force = not current_image
        else:
            should_force = (
                state_mode == "none" or not current_image
                or (state_mode == "legacy" and is_stock_wallpaper(current_image or ""))
                or (state_mode == "v2" and is_stock_wallpaper(current_image or ""))
            )
            image = str(wallpaper) if should_force else str(current_image)
            style = "5" if should_force or not valid_image_style(current_style) else str(current_style)
        expected[path] = (image, style if valid_image_style(style) else "5")
        force[path] = should_force

    all_verified = False
    for attempt in range(2):
        known_paths = set(properties)
        operations_ok: dict[str, bool] = {}
        for target in targets:
            path, style_path = target.last_image, target.image_style
            image, style = expected[path]
            now_image = _query(runner, "xfce4-desktop", path)
            image_ok = True
            if force[path] or now_image != image:
                image_ok = _set_verify(runner, path, "string", image, known_paths)
                if image_ok:
                    known_paths.add(path)
            now_style = _query(runner, "xfce4-desktop", style_path)
            style_ok = True
            if force[path] or now_style != style:
                style_ok = _set_verify(runner, style_path, "int", style, known_paths)
                if style_ok:
                    known_paths.add(style_path)
            operations_ok[path] = image_ok and style_ok

        reload_result = _call(runner, ["xfdesktop", "--reload"])
        sleeper(1.0)
        all_verified = reload_result.returncode == 0
        for target in targets:
            path, style_path = target.last_image, target.image_style
            image, style = expected[path]
            after_image = _query(runner, "xfce4-desktop", path)
            after_style = _query(runner, "xfce4-desktop", style_path)
            verified = (
                operations_ok.get(path, False) and reload_result.returncode == 0
                and after_image == image and after_style == style and valid_image_style(after_style)
            )
            all_verified = all_verified and verified
            logger(
                "[TraceOS] stage=TRACEOS_DESKTOP_BRANDING_TARGET "
                f"result={'PASS' if verified else 'FAIL'} output={_encode(target.output)} "
                f"target_mode={_encode(target.mode)} path={_encode(path)} "
                f"before_image={_encode(before[path][0])} "
                f"expected_image={_encode(image)} after_image={_encode(after_image)} "
                f"before_style={_encode(before[path][1])} expected_style={style} "
                f"after_style={_encode(after_style)} forced={'yes' if force[path] else 'no'}"
            )
        if all_verified:
            break
        if attempt == 0:
            retry_dump = _call(runner, ["xfconf-query", "-c", "xfce4-desktop", "-lv"])
            if retry_dump.returncode == 0:
                properties = parse_property_dump(retry_dump.stdout)

    if not all_verified:
        _emit(logger, "FAIL", reason="wallpaper_or_style_readback_failed",
              outputs=",".join(m.name for m in active_outputs),
              backdrop_targets=",".join(t.last_image for t in targets),
              missing_outputs=",".join(missing) or "none", targets=len(targets),
              xsettings_theme=theme, png_width=width, png_height=height, png_sha256=checksum)
        return False

    state_targets: dict[str, dict[str, str]] = {}
    for target in targets:
        image = _query(runner, "xfce4-desktop", target.last_image)
        style = _query(runner, "xfce4-desktop", target.image_style)
        if image is None or not valid_image_style(style):
            _emit(logger, "FAIL", reason="final_state_readback_failed",
                  output=target.output, path=target.last_image, targets=len(targets),
                  xsettings_theme=theme, png_width=width, png_height=height, png_sha256=checksum)
            return False
        state_targets[target.last_image] = {"image": image, "style": style}

    try:
        state.parent.mkdir(parents=True, exist_ok=True)
        temporary = state.with_name(state.name + ".tmp")
        temporary.write_text(json.dumps(
            {"version": STATE_VERSION, "targets": state_targets}, sort_keys=True, indent=2
        ) + "\n", encoding="utf-8")
        temporary.replace(state)
    except OSError as exc:
        _emit(logger, "FAIL", reason="completion_marker_write_failed", detail=str(exc),
              targets=len(targets), xsettings_theme=theme, png_width=width,
              png_height=height, png_sha256=checksum)
        return False

    # Record the post-write xfconf-query -lv snapshot as the authoritative
    # runtime state. The initial dump above is useful for diagnosing changes;
    # this one proves the selected image and image-style after readback.
    final_dump = _call(runner, ["xfconf-query", "-c", "xfce4-desktop", "-lv"])
    if final_dump.returncode != 0:
        _emit(logger, "FAIL", reason="final_xfconf_snapshot_failed",
              targets=len(targets), xsettings_theme=theme, png_width=width,
              png_height=height, png_sha256=checksum)
        return False
    for path, value in sorted(parse_property_dump(final_dump.stdout).items()):
        _emit_runtime_property(logger, "xfconf_property_final", path=path, value=value)

    _emit(logger, "PASS", outputs=",".join(m.name for m in active_outputs),
          targets=len(targets), backdrop_targets=",".join(t.last_image for t in targets),
          target_modes=",".join(t.mode for t in targets),
          discovered_backdrops=",".join(discovered_backdrops) or "none",
          missing_outputs=",".join(missing) or "none", xsettings_theme=theme,
          png_width=width, png_height=height, png_sha256=checksum,
          marker_version=STATE_VERSION, mode=state_mode)
    return True


if __name__ == "__main__":
    raise SystemExit(0 if setup_wallpaper() else 1)
