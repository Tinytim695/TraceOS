#!/usr/bin/env python3
import base64,hashlib,re,subprocess,sys,time,tarfile,io
from pathlib import Path
iso=Path(sys.argv[1] if len(sys.argv)>1 else "live-image-amd64.hybrid.iso"); out=Path(sys.argv[2] if len(sys.argv)>2 else "traceos-cli-e2e"); state=Path(sys.argv[3] if len(sys.argv)>3 else "traceos-cli-e2e-state"); out.mkdir(exist_ok=True); state.mkdir(exist_ok=True)
serial=state/"serial.log"; launch=state/"launch.log"
p=subprocess.Popen(["qemu-system-x86_64","-accel","tcg,thread=multi","-cpu","max","-m","3072","-smp","2","-vga","std","-nic","none","-drive",f"file={iso},media=cdrom,readonly=on,format=raw","-boot","order=d","-fw_cfg","name=opt/traceos/ci-e2e,string=1","-display","none","-serial",f"file:{serial}","-monitor","none","-snapshot","-no-reboot","-no-shutdown"],stdout=launch.open("w"),stderr=subprocess.STDOUT)
started=done=False
try:
    for _ in range(420):
        s=serial.read_text(errors="replace") if serial.exists() else ""; started|="TRACEOS_CI_E2E_STARTED=1" in s; done|="TRACEOS_CI_E2E_DONE=1" in s
        if done or p.poll() is not None:break
        time.sleep(1)
finally:
    if p.poll() is None:p.terminate()
    try:p.wait(timeout=15)
    except subprocess.TimeoutExpired:p.kill();p.wait()
if not started:
    (out/"result.txt").write_text("STATUS=SETUP_UNKNOWN\nREASON=guest_did_not_announce_fw_cfg_runner\n"); raise SystemExit(2)
if not done:
    (out/"result.txt").write_text("STATUS=FAIL\nREASON=guest_runner_did_not_complete\n"); raise SystemExit(1)
s=serial.read_text(errors="replace"); m=re.search(r"TRACEOS_CI_E2E_BUNDLE_BEGIN size=(\d+) sha256=([0-9a-f]{64})",s)
if not m or "TRACEOS_CI_E2E_BUNDLE_END" not in s:
    (out/"result.txt").write_text("STATUS=FAIL\nREASON=missing_or_incomplete_bundle\n"); raise SystemExit(1)
size=int(m.group(1)); expected=m.group(2); payload=s.split(m.group(0),1)[1].split("TRACEOS_CI_E2E_BUNDLE_END",1)[0]
try:data=base64.b64decode("".join(payload.splitlines()),validate=True)
except Exception as e:
    (out/"result.txt").write_text(f"STATUS=FAIL\nREASON=invalid_base64:{e}\n"); raise SystemExit(1)
if len(data)!=size or hashlib.sha256(data).hexdigest()!=expected:
    (out/"result.txt").write_text("STATUS=FAIL\nREASON=bundle_size_or_sha_mismatch\n"); raise SystemExit(1)
allowed={'matrix.txt','case.json','case-new-state.txt','current-case-probe.txt','evidence-add-state.txt','evidence-verify-pass-state.txt','evidence-verify-tamper-state.txt','report-state.txt','timeline-state.txt','source.sha256','ledger-check.txt','vault-pre.txt','vault-post.txt','evidence-add.stdout','evidence-add.stderr','evidence-add.exit','evidence-verify-pass.stdout','evidence-verify-pass.stderr','evidence-verify-pass.exit','evidence-verify-tamper.stdout','evidence-verify-tamper.stderr','evidence-verify-tamper.exit','report.stdout','report.stderr','report.exit','timeline.stdout','timeline.stderr','timeline.exit'}
with tarfile.open(fileobj=io.BytesIO(data),mode="r:") as tf:
    names=tf.getnames()
    if set(names)-allowed or any("/" in n or n.startswith(".") for n in names):
        (out/"result.txt").write_text("STATUS=FAIL\nREASON=disallowed_bundle_member\n"); raise SystemExit(1)
    tf.extractall(out)
status="UNKNOWN"
if (out/"matrix.txt").exists():
    mm=re.search(r"^STATUS=(\S+)",(out/"matrix.txt").read_text(),re.M); status=mm.group(1) if mm else "UNKNOWN"
(out/"result.txt").write_text(f"STATUS={'PASS' if status=='PASS' else 'FAIL'}\nGUEST_MATRIX_STATUS={status}\n")
print((out/"matrix.txt").read_text(),end=""); raise SystemExit(0 if status=="PASS" else 1)
