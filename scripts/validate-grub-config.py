#!/usr/bin/env python3
"""Validate TraceOS GRUB entries extracted from a built live ISO."""

from __future__ import annotations

import re
import sys
from pathlib import Path


class GrubValidationError(ValueError):
    """Raised when an extracted GRUB payload violates the boot contract."""


AMNESIC_TITLE = "TraceOS Amnesic (no persistent storage)"
FAILSAFE_TITLE = "TraceOS Failsafe (Amnesic)"


def _entry_body(text: str, title: str) -> str:
    pattern = re.compile(
        r"""(?ms)^[ \t]*menuentry[ \t]+["']"""
        + re.escape(title)
        + r"""["'][^\n{]*\{(.*?)^[ \t]*\}"""
    )
    match = pattern.search(text)
    if not match:
        raise GrubValidationError(f"missing menu entry {title!r}")
    return match.group(1)


def _validate_live_entry(
    text: str,
    title: str,
    required_args: tuple[str, ...],
    *,
    failsafe: bool = False,
) -> None:
    body = _entry_body(text, title)
    kernel_lines = re.findall(r"(?m)^[ \t]*linux[ \t]+(.+)$", body)
    initrd_lines = re.findall(r"(?m)^[ \t]*initrd[ \t]+(.+)$", body)

    if len(kernel_lines) != 1 or len(initrd_lines) != 1:
        raise GrubValidationError(
            f"{title!r} must contain exactly one linux line and one initrd line"
        )

    kernel = kernel_lines[0].strip()
    initrd = initrd_lines[0].strip()
    kernel_fields = kernel.split()
    if not kernel_fields:
        raise GrubValidationError(f"{title!r} has an empty kernel line")

    if "@" in kernel or "@" in initrd:
        raise GrubValidationError(
            f"unresolved or malformed placeholder in {title!r}: "
            f"linux={kernel!r}, initrd={initrd!r}"
        )

    if not kernel_fields[0].startswith("/live/vmlinuz"):
        raise GrubValidationError(
            f"kernel path is not resolved under /live in {title!r}: "
            f"{kernel_fields[0]!r}"
        )
    if not initrd.startswith("/live/initrd.img"):
        raise GrubValidationError(
            f"initrd path is not resolved under /live in {title!r}: {initrd!r}"
        )

    args = kernel_fields[1:]
    if "findiso=${iso_path}" not in args:
        raise GrubValidationError(
            f"{title!r} is missing the findiso=${{iso_path}} locator"
        )

    missing = [arg for arg in required_args if arg not in args]
    if missing:
        raise GrubValidationError(
            f"{title!r} lacks required kernel arguments: {missing!r}"
        )

    persistence_args = [
        arg for arg in args
        if arg == "persistence" or arg.startswith("persistence-")
    ]
    if persistence_args:
        raise GrubValidationError(
            f"amnesic entry {title!r} enables persistence: {persistence_args!r}"
        )

    if failsafe and "nomodeset" not in args:
        raise GrubValidationError(
            "failsafe entry must include the nomodeset fallback"
        )


def validate_grub_config(grub_text: str, generated_config_text: str) -> None:
    """Validate extracted GRUB config and its sourced context file."""
    if not generated_config_text.strip():
        raise GrubValidationError(
            "generated /boot/grub/config.cfg is missing or empty"
        )

    if not re.search(
        r"(?m)^[ \t]*source[ \t]+/boot/grub/config\.cfg[ \t]*$",
        grub_text,
    ):
        raise GrubValidationError(
            "/boot/grub/config.cfg is not sourced by generated grub.cfg"
        )

    if not re.search(r"(?m)^[ \t]*set default=0[ \t]*$", grub_text):
        raise GrubValidationError("default menu index is not zero")

    traceos_entries = re.findall(
        r"""(?m)^[ \t]*menuentry[ \t]+["'](TraceOS [^"']+)["']""",
        grub_text,
    )
    if not traceos_entries:
        raise GrubValidationError("no TraceOS menu entries found")
    if traceos_entries[0] != AMNESIC_TITLE:
        raise GrubValidationError(
            "first TraceOS menu entry is not Amnesic "
            f"(found {traceos_entries[0]!r})"
        )

    _validate_live_entry(
        grub_text,
        AMNESIC_TITLE,
        ("boot=live", "username=traceos", "nopersistence"),
    )
    _validate_live_entry(
        grub_text,
        FAILSAFE_TITLE,
        ("boot=live", "username=traceos", "nopersistence", "nomodeset"),
        failsafe=True,
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "Usage: validate-grub-config.py GENERATED_GRUB_CFG GENERATED_CONFIG_CFG",
            file=sys.stderr,
        )
        return 2

    grub_path = Path(argv[1])
    context_path = Path(argv[2])
    try:
        grub_text = grub_path.read_text(encoding="utf-8")
        config_text = context_path.read_text(encoding="utf-8")
        validate_grub_config(grub_text, config_text)
    except (OSError, UnicodeError, GrubValidationError) as exc:
        print(f"[TraceOS] GRUB validation failed: {exc}", file=sys.stderr)
        return 1

    print("[TraceOS] Generated GRUB source, Amnesic and Failsafe entries: PASS")
    print("[TraceOS] Generated /boot/grub/config.cfg artifact: present and non-empty")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
