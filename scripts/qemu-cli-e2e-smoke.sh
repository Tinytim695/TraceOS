#!/usr/bin/env python3
import base64
import csv
import hashlib
import io
import json
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

    # Do not trust the guest matrix by itself. Re-validate the important
    # synthetic evidence independently on the CI host before declaring PASS.
    audit_lines = []
    audit_state = [True]

    def audit(name, ok, detail=""):
        ok = bool(ok)
        audit_state[0] = audit_state[0] and ok
        suffix = f" {detail}" if detail else ""
        audit_lines.append(f"{name}={'PASS' if ok else 'FAIL'}{suffix}")

    try:
        case_doc = json.loads((out / "case.json").read_text())
        case_id = case_doc["case_id"]
        audit("CASE_ID_FORMAT",
              bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", case_id)))
    except Exception as exc:
        case_id = ""
        audit("CASE_JSON", False, f"error={exc!r}")

    state_files = [
        "case-new-state.txt",
        "current-case-probe.txt",
        "evidence-add-state.txt",
        "evidence-verify-pass-state.txt",
        "evidence-verify-tamper-state.txt",
        "report-state.txt",
        "timeline-state.txt",
    ]
    observed_ids = []
    for state_name in state_files:
        state_path = out / state_name
        state_text = state_path.read_text(errors="replace") if state_path.exists() else ""
        match = re.search(r"^case_id=(\S+)$", state_text, re.M)
        observed = match.group(1) if match else ""
        observed_ids.append(observed)
        audit(f"STATE_{state_name}", bool(case_id and observed == case_id))

    audit("STATE_CASE_ID_CONSISTENT",
          bool(case_id and observed_ids and all(value == case_id for value in observed_ids)))

    def exit_code(name):
        try:
            return int((out / f"{name}.exit").read_text().strip())
        except Exception:
            return None

    audit("CASE_NEW_EXIT", exit_code("case-new") == 0)
    audit("EVIDENCE_ADD_EXIT", exit_code("evidence-add") == 0)
    audit("VERIFY_PASS_EXIT", exit_code("evidence-verify-pass") == 0)
    audit("VERIFY_TAMPER_NONZERO", exit_code("evidence-verify-tamper") not in (None, 0))
    audit("REPORT_EXIT", exit_code("report") == 0)
    audit("TIMELINE_EXIT", exit_code("timeline") == 0)

    verify_pass_stdout = (out / "evidence-verify-pass.stdout").read_text(errors="replace") if (out / "evidence-verify-pass.stdout").exists() else ""
    verify_tamper_stdout = (out / "evidence-verify-tamper.stdout").read_text(errors="replace") if (out / "evidence-verify-tamper.stdout").exists() else ""
    timeline_stdout = (out / "timeline.stdout").read_text(errors="replace") if (out / "timeline.stdout").exists() else ""
    audit("VERIFY_PASS_OUTPUT", "1 checked, 0 failed" in verify_pass_stdout)
    audit("VERIFY_TAMPER_HASH_MISMATCH",
          "expected=" in verify_tamper_stdout and "missing or unsafe vault copy" not in verify_tamper_stdout)

    source_hash = ""
    try:
        source_text = (out / "source.sha256").read_text()
        source_hash = re.search(r"^sha256=([0-9a-f]{64})$", source_text, re.M).group(1)
        audit("SOURCE_HASH_FORMAT", True)
    except Exception as exc:
        audit("SOURCE_HASH_FORMAT", False, f"error={exc!r}")

    ledger_hash = ""
    ledger_vault = ""
    try:
        with (out / "evidence.tsv").open(newline="") as handle:
            rows = list(csv.reader(handle, delimiter="\t"))
        audit("LEDGER_ONE_RECORD", len(rows) == 2)
        if len(rows) == 2 and len(rows[1]) == 6:
            ledger_hash = rows[1][3]
            ledger_vault = rows[1][2]
        audit("LEDGER_HASH_MATCHES_SOURCE", bool(source_hash and ledger_hash == source_hash))
        audit("LEDGER_VAULT_PATH",
              bool(case_id and re.fullmatch(rf"/home/traceos/Cases/{re.escape(case_id)}/evidence/[^/]+", ledger_vault)))
    except Exception as exc:
        audit("LEDGER_PARSE", False, f"error={exc!r}")

    vault_pre_hash = ""
    vault_post_hash = ""
    try:
        pre = (out / "vault-pre.txt").read_text()
        post = (out / "vault-post.txt").read_text()
        vault_pre_hash = re.search(r"^sha256=([0-9a-f]{64})$", pre, re.M).group(1)
        vault_post_hash = re.search(r"^sha256=([0-9a-f]{64})$", post, re.M).group(1)
        audit("VAULT_PRE_HASH_MATCH", bool(source_hash and vault_pre_hash == source_hash))
        audit("VAULT_POST_HASH_CHANGED",
              bool(vault_post_hash and vault_pre_hash and vault_post_hash != vault_pre_hash))
        audit("VAULT_POST_FILE_METADATA", "regular=yes" in post)
    except Exception as exc:
        audit("VAULT_HASH_PROBES", False, f"error={exc!r}")

    report_text = (out / "report.md").read_text(errors="replace") if (out / "report.md").exists() else ""
    audit("REPORT_REFERENCES_VAULT",
          bool(ledger_vault) and ledger_vault.rsplit("/", 1)[-1] in report_text)
    audit("REPORT_REFERENCES_LEDGER_HASH",
          bool(ledger_hash) and ledger_hash in report_text)
    audit("TIMELINE_REFERENCES_VAULT",
          bool(ledger_vault) and ledger_vault.rsplit("/", 1)[-1] in timeline_stdout)

    required_success_members = {
        "matrix.txt", "case.json", *state_files, "source.sha256",
        "ledger-check.txt", "vault-pre.txt", "vault-post.txt",
        "evidence.tsv", "report.md",
        "evidence-add.stdout", "evidence-add.stderr", "evidence-add.exit",
        "evidence-verify-pass.stdout", "evidence-verify-pass.stderr", "evidence-verify-pass.exit",
        "evidence-verify-tamper.stdout", "evidence-verify-tamper.stderr", "evidence-verify-tamper.exit",
        "report.stdout", "report.stderr", "report.exit",
        "timeline.stdout", "timeline.stderr", "timeline.exit"
    }
    present_members = {p.name for p in out.iterdir() if p.is_file() and p.name != "result.txt"}
    audit("REQUIRED_BUNDLE_MEMBERS", required_success_members.issubset(present_members))

    audit_ok = audit_state[0]
    (out / "host-audit.txt").write_text(
        "TRACEOS_HOST_INDEPENDENT_AUDIT=1\n"
        + "\n".join(audit_lines)
        + "\nOVERALL=" + ("PASS" if audit_ok else "FAIL") + "\n"
    )

    if status == "PASS" and audit_ok:
        write_result("PASS", "validated_guest_matrix_and_host_audit")
        raise SystemExit(0)
    if status == "PASS" and not audit_ok:
        write_result("FAIL", "guest_matrix_passed_host_audit_failed")
        raise SystemExit(1)
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
