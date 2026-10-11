#!/usr/bin/env python3
"""Host fixture tests for the TraceOS generated-GRUB validator."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

VALID_GRUB = """set timeout=8
set default=0
source /boot/grub/config.cfg

menuentry "TraceOS Amnesic (no persistent storage)" {
    linux /live/vmlinuz-test boot=live components username=traceos hostname=traceos console=ttyS0,115200n8 findiso=${iso_path} nopersistence splash
    initrd /live/initrd.img-test
}

menuentry "TraceOS Persistent" {
    linux /live/vmlinuz-test boot=live username=traceos findiso=${iso_path} persistence splash
    initrd /live/initrd.img-test
}

menuentry "TraceOS Failsafe (Amnesic)" {
    linux /live/vmlinuz-test boot=live components username=traceos hostname=traceos console=ttyS0,115200n8 findiso=${iso_path} nopersistence nomodeset
    initrd /live/initrd.img-test
}
"""
VALID_CONTEXT = "# generated GRUB context fixture\nset iso_path=/traceos.iso\n"

MODULE_PATH = Path(__file__).with_name("validate-grub-config.py")
SPEC = importlib.util.spec_from_file_location("traceos_validate_grub_config", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Could not load the GRUB validator module")
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


def expect_pass(name: str, grub: str, context: str = VALID_CONTEXT) -> None:
    try:
        VALIDATOR.validate_grub_config(grub, context)
    except VALIDATOR.GrubValidationError as exc:
        raise AssertionError(f"{name}: expected PASS, got {exc}") from exc
    print(f"PASS {name}")


def expect_fail(name: str, grub: str, context: str = VALID_CONTEXT) -> None:
    try:
        VALIDATOR.validate_grub_config(grub, context)
    except VALIDATOR.GrubValidationError:
        print(f"PASS {name} (rejected as expected)")
        return
    raise AssertionError(f"{name}: expected the validator to reject this fixture")


def main() -> int:
    expect_pass("valid generated GRUB entries", VALID_GRUB)

    broken_failsafe = VALID_GRUB.replace(
        "linux /live/vmlinuz-test boot=live components username=traceos hostname=traceos console=ttyS0,115200n8 findiso=${iso_path} nopersistence nomodeset",
        "linux /live/vmlinuz-test @boot=live components username=traceos hostname=traceos console=ttyS0,115200n8 findiso=${iso_path}_FAILSAFE@ nopersistence",
    )
    expect_fail("historical malformed failsafe line", broken_failsafe)

    expect_fail(
        "unresolved APPEND_LIVE placeholder",
        VALID_GRUB.replace(
            "boot=live components username=traceos hostname=traceos console=ttyS0,115200n8 findiso=${iso_path} nopersistence nomodeset",
            "@APPEND_LIVE@ nopersistence nomodeset",
        ),
    )
    expect_fail(
        "unresolved KERNEL_LIVE placeholder",
        VALID_GRUB.replace(
            "linux /live/vmlinuz-test boot=live",
            "linux @KERNEL_LIVE@ boot=live",
            1,
        ),
    )
    expect_fail(
        "unresolved INITRD_LIVE placeholder",
        VALID_GRUB.replace(
            "initrd /live/initrd.img-test",
            "initrd @INITRD_LIVE@",
            1,
        ),
    )
    expect_fail(
        "arbitrary unresolved at-sign in kernel arguments",
        VALID_GRUB.replace(
            "findiso=${iso_path} nopersistence nomodeset",
            "findiso=${iso_path} @UNRESOLVED@ nopersistence nomodeset",
        ),
    )
    expect_fail(
        "wrong default index",
        VALID_GRUB.replace("set default=0", "set default=1", 1),
    )
    expect_fail(
        "missing generated config source",
        VALID_GRUB.replace("source /boot/grub/config.cfg\n", "", 1),
    )

    unrelated_before_traceos = VALID_GRUB.replace(
        'menuentry "TraceOS Amnesic (no persistent storage)" {',
        'menuentry "Unrelated platform entry" {\n    set gfxpayload=keep\n}\n\n'
        'menuentry "TraceOS Amnesic (no persistent storage)" {',
        1,
    )
    expect_pass(
        "unrelated global menuentry does not mask TraceOS ordering",
        unrelated_before_traceos,
    )

    expect_fail(
        "persistence enabled in Amnesic entry",
        VALID_GRUB.replace(
            "findiso=${iso_path} nopersistence splash",
            "findiso=${iso_path} nopersistence persistence splash",
            1,
        ),
    )
    expect_fail(
        "persistence enabled in Failsafe entry",
        VALID_GRUB.replace(
            "findiso=${iso_path} nopersistence nomodeset",
            "findiso=${iso_path} nopersistence persistence-encryption=luks nomodeset",
        ),
    )
    expect_fail(
        "failsafe missing nomodeset",
        VALID_GRUB.replace(
            "findiso=${iso_path} nopersistence nomodeset",
            "findiso=${iso_path} nopersistence",
        ),
    )
    expect_fail(
        "generated config artifact is missing or empty",
        VALID_GRUB,
        "",
    )

    print("[TraceOS] GRUB validator fixtures: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
