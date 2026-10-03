#!/usr/bin/env python3
import base64
import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

iso = Path(sys.argv[1] if len(sys.argv) > 1 else "live-image-amd64.hybrid.iso")
out = Path(sys.argv[2] if len(sys.argv) > 2 else "traceos-cli-e2e")
state = Path(sys.argv[3] if len(sys.argv) > 3 else "traceos-cli-e2e-state")
out.mkdir(exist_ok=True)
state.mkdir(exist_ok=True)
serial = state / "serial.log"
launch = state / "launch.log"

p = subprocess.Popen(
    ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-cpu", "max",
     "-m", "3072", "-smp", "2", "-vga", "std", "-nic", "none",
     "-drive", f"file={iso},media=cdrom,readonly=on,format=raw",
     "-boot", "order=d", "-fw_cfg", "name=opt/traceos/ci-e2e,string=1",
     "-display", "none", "-serial", f"file:{serial}", "-monitor", "none",
     "-snapshot", "-no-reboot", "-no-shutdown"],
    stdout=launch.open("w"), stderr=subprocess.STDOUT)

started = done = False
last_stage = "QEMU_LAUNCHED"
result_written = False

def write_result(status, reason):
    global result_written
    (out / "result.txt").write_text(
        f"STATUS={status}\nLAST_STAGE={last_stage}\nREASON={reason}\n")
    result_written = True

try:
    for _ in range(600):
        s = serial.read_text(errors="replace") if serial.exists() else ""
        if "TRACEOS_CI_E2E_PREFLIGHT=1" in s:
            last_stage = "PREFLIGHT"
        if "TRACEOS_CI_E2E_STARTED=1" in s:
            started = True
            last_stage = "GUEST_STARTED"
        if "TRACEOS_CI_E2E_DONE=1" in s:
            done = True
            last_stage = "GUEST_DONE"
        if done or p.poll() is not None:
            if p.poll() is not None and not done:
                last_stage = "QEMU_EXIT"
            break
        time.sleep(1)

    if not started:
        write_result("SETUP_UNKNOWN", "guest_did_not_announce_fw_cfg_runner")
        raise SystemExit(2)
    if not done:
        write_result("FAIL", "guest_runner_did_not_complete")
        raise SystemExit(1)

    s = serial.read_text(errors="replace")
    m = re.search(r"TRACEOS_CI_E2E_BUNDLE_BEGIN size=(\d+) sha256=([0-9a-f]{64})", s)
    if not m:
        write_result("FAIL", "missing_bundle_begin")
        raise SystemExit(1)
    last_stage = "BUNDLE_BEGIN"
    if "TRACEOS_CI_E2E_BUNDLE_END" not in s:
        write_result("FAIL", "missing_bundle_end")
        raise SystemExit(1)
    last_stage = "BUNDLE_END"

    size = int(m.group(1))
    expected = m.group(2)
    payload = s.split(m.group(0), 1)[1].split("TRACEOS_CI_E2E_BUNDLE_END", 1)[0]
    try:
        data = base64.b64decode("".join(payload.splitlines()), validate=True)
    except Exception as e:
        write_result("FAIL", f"invalid_base64:{e}")
        raise SystemExit(1)

    if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
        write_result("FAIL", "bundle_size_or_sha_mismatch")
        raise SystemExit(1)

    allowed = {
        "matrix.txt", "case.json", "case-new-state.txt", "current-case-probe.txt",
        "evidence-add-state.txt", "evidence-verify-pass-state.txt",
        "evidence-verify-tamper-state.txt", "report-state.txt", "timeline-state.txt",
        "source.sha256", "ledger-check.txt", "vault-pre.txt", "vault-post.txt",
        "evidence.tsv", "report.md",
        "evidence-add.stdout", "evidence-add.stderr", "evidence-add.exit",
        "evidence-verify-pass.stdout", "evidence-verify-pass.stderr", "evidence-verify-pass.exit",
        "evidence-verify-tamper.stdout", "evidence-verify-tamper.stderr", "evidence-verify-tamper.exit",
        "report.stdout", "report.stderr", "report.exit",
        "timeline.stdout", "timeline.stderr", "timeline.exit"}

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
        names = tf.getnames()
        if set(names) - allowed or any("/" in n or n.startswith(".") for n in names):
            write_result("FAIL", "disallowed_bundle_member")
            raise SystemExit(1)
        tf.extractall(out)

    status = "UNKNOWN"
    matrix = out / "matrix.txt"
    if matrix.exists():
        mm = re.search(r"^STATUS=(\S+)", matrix.read_text(), re.M)
        status = mm.group(1) if mm else "UNKNOWN"

    if status == "PASS":
        write_result("PASS", "validated_guest_matrix")
        raise SystemExit(0)
    write_result("FAIL", f"guest_matrix_status_{status}")
    raise SystemExit(1)

except SystemExit:
    raise
except Exception as exc:
    write_result("FAIL", f"host_exception:{exc}")
    raise SystemExit(1)
finally:
    try:
        if p.poll() is None:
            p.terminate()
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    finally:
        for src in (serial, launch):
            if src.exists():
                shutil.copy2(src, out / src.name)
        if not result_written:
            write_result("FAIL", "host_exit_without_result")
