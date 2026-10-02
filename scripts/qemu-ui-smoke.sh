#!/usr/bin/env bash
set -euo pipefail

ISO="${1:-live-image-amd64.hybrid.iso}"
OUT="${2:-traceos-ui-screenshots}"
STATE="${3:-traceos-ui}"

test -s "$ISO"
rm -rf "$OUT" "$STATE"
mkdir -p "$OUT" "$STATE"

extract_boot_config() {
    local iso_path="$1"
    local out_path="$2"
    if xorriso -osirrox on -indev "$ISO" -extract "$iso_path" "$out_path" >/dev/null 2>&1; then
        echo "[TraceOS] Extracted $iso_path -> $out_path"
        grep -En '^[[:space:]]*(APPEND|append|linux)[[:space:]]' "$out_path" || true
    else
        echo "[TraceOS] Could not extract $iso_path from the ISO." >&2
        return 1
    fi
}

# Validate the actual bootloader payloads inside the ISO before spending five
# minutes on the graphical boot. The BIOS El Torito path is the path used by
# QEMU below, so it must carry the same live username as the GRUB path.
extract_boot_config /isolinux/isolinux.cfg "$OUT/traceos-generated-isolinux.cfg"
extract_boot_config /boot/grub/grub.cfg "$OUT/traceos-generated-grub.cfg" || true

if ! grep -Eq '(^|[[:space:]])username=traceos([[:space:]]|$)' "$OUT/traceos-generated-isolinux.cfg"; then
    echo "[TraceOS] Generated ISOLINUX config is missing username=traceos." >&2
    exit 1
fi

if [ -s "$OUT/traceos-generated-grub.cfg" ] && ! grep -Eq '(^|[[:space:]])username=traceos([[:space:]]|$)' "$OUT/traceos-generated-grub.cfg"; then
    echo "[TraceOS] Generated GRUB config is missing username=traceos." >&2
    exit 1
fi


cleanup() {
    if [[ -n "${QEMU_PID:-}" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    mkdir -p "$OUT"
    for log_file in "$STATE"/*.log; do
        if [[ -f "$log_file" ]]; then
            cp -f "$log_file" "$OUT/$(basename "$log_file")"
        fi
    done
}
trap cleanup EXIT

hmp_command() {
    local monitor="$1"
    local command="$2"
    local log_path="$3"

    python3 - "$monitor" "$command" "$log_path" <<'PY'
import datetime
import re
import socket
import sys
import time

monitor, command, log_path = sys.argv[1], sys.argv[2], sys.argv[3]
prompt = b"(qemu)"

def read_until_prompt(sock: socket.socket, deadline_seconds: float = 12.0) -> bytes:
    deadline = time.monotonic() + deadline_seconds
    data = bytearray()
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
        if data.rstrip().endswith(prompt):
            return bytes(data)
    raise RuntimeError("QEMU HMP prompt was not observed before deadline")

stamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(1)
    sock.connect(monitor)
    banner = read_until_prompt(sock)
    sock.sendall((command + "\n").encode("utf-8"))
    response = read_until_prompt(sock)

banner_text = banner.decode("utf-8", "replace")
response_text = response.decode("utf-8", "replace")
error_pattern = re.compile(r"(?im)^\\s*(?:Error:|unknown command|invalid parameter|command .* failed|failed to .*|could not .*|HMP .*error)")
error_match = error_pattern.search(response_text)

with open(log_path, "w", encoding="utf-8") as handle:
    handle.write(f"timestamp_utc={stamp}\n")
    handle.write(f"command={command}\n")
    handle.write("initial_monitor_until_prompt:\n")
    handle.write(banner_text)
    handle.write("\ncommand_response_until_prompt:\n")
    handle.write(response_text)
    handle.write("\nhmp_error_detected=" + ("yes" if error_match else "no") + "\n")

print(f"[TraceOS] HMP command: {command}")
print(f"[TraceOS] HMP initial bytes: {len(banner)} response bytes: {len(response)}")
if error_match:
    print(f"[TraceOS] HMP ERROR: {error_match.group(0).strip()}", file=sys.stderr)
    raise SystemExit(2)
print("[TraceOS] HMP command accepted through the next prompt.")
PY
}

capture_screendump() {
    local monitor="$1"
    local ppm="$2"
    local log_path="$3"
    rm -f "$ppm"
    local requested_ns
    requested_ns="$(date +%s%N)"

    hmp_command "$monitor" "screendump $ppm" "$log_path"

    for _ in $(seq 1 20); do
        if [[ -s "$ppm" ]] && python3 - "$ppm" "$requested_ns" <<'PY'
import os
import sys

path, requested_ns = sys.argv[1], int(sys.argv[2])
try:
    fresh = os.stat(path).st_mtime_ns >= requested_ns
except FileNotFoundError:
    fresh = False
raise SystemExit(0 if fresh else 1)
PY
        then
            echo "[TraceOS] Fresh framebuffer confirmed: $ppm"
            return 0
        fi
        sleep 1
    done

    echo "[TraceOS] Screendump did not produce a fresh framebuffer: $ppm" >&2
    return 1
}

capture_page() {
    local page="$1"
    local keep_alive="${2:-false}"
    local monitor="$STATE/monitor-$page.sock"
    local vnc_socket="$STATE/vnc-$page.sock"
    local ppm="$OUT/traceos-$page.ppm"
    local png="$OUT/traceos-$page.png"
    rm -f "$monitor" "$vnc_socket" "$ppm" "$png"

    echo "[TraceOS] QEMU graphical page: $page"

    # Boot the actual ISO through its El Torito boot path. Do not use
    # QEMU -append here: that option is for direct kernel boot and is not
    # the way to pass arguments through an ISO's GRUB bootloader.
    qemu-system-x86_64 \
        -accel tcg,thread=multi \
        -cpu max \
        -m 3072 \
        -smp 2 \
        -vga std \
        -nic none \
        -drive "file=$ISO,media=cdrom,readonly=on,format=raw" \
        -boot order=d \
        -display "vnc=unix:$vnc_socket" \
        -monitor "unix:$monitor,server=on,wait=off" \
        -serial "file:$STATE/serial-$page.log" \
        -snapshot \
        -no-reboot \
        >"$STATE/launch-$page.log" 2>&1 &
    QEMU_PID=$!

    for _ in $(seq 1 30); do
        if [[ -S "$monitor" ]]; then
            break
        fi
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "[TraceOS] QEMU exited before opening its monitor." >&2
            cat "$STATE/launch-$page.log" >&2 || true
            exit 1
        fi
        sleep 1
    done
    if [[ ! -S "$monitor" ]]; then
        echo "[TraceOS] QEMU monitor socket was not created." >&2
        cat "$STATE/launch-$page.log" >&2 || true
        exit 1
    fi

    # TCG is slow. Give the real ISO boot path time to reach LightDM,
    # XFCE and the TraceOS welcome/control centre.
    # TCG boot time can vary on shared CI runners. Allow a longer window before
    # declaring the real graphical desktop absent.
    sleep 300

    capture_screendump "$monitor" "$ppm" "$STATE/monitor-$page-screendump.log"

    test -s "$ppm"
    convert "$ppm" -resize 1280x720 -strip "$png"
    identify "$png"
    test -s "$png"

    spread="$(convert "$png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
    echo "[TraceOS] $page framebuffer standard deviation: $spread"
    if ! awk "BEGIN { exit !($spread > 0.02) }"; then
        echo "[TraceOS] Graphical framebuffer is still blank/static." >&2
        echo "[TraceOS] Serial tail:" >&2
        tail -n 120 "$STATE/serial-$page.log" >&2 || true
        echo "[TraceOS] QEMU launch log:" >&2
        tail -n 80 "$STATE/launch-$page.log" >&2 || true
        exit 1
    fi

    # A bootloader/error screen can have lots of pixel variation too. Require
    # actual TraceOS theme pixels before treating the screenshot as a desktop.
    histogram="$(convert "$png" -format "%c" histogram:info:-)"
    accent_fraction="$(convert "$png" -fuzz 10% -fill white -opaque "#72F1E8" -fill black +opaque white -format "%[fx:mean]" info:)"
    bg_fraction="$(convert "$png" -fuzz 10% -fill white -opaque "#050811" -fill black +opaque white -format "%[fx:mean]" info:)"
    echo "[TraceOS] accent pixel fraction: $accent_fraction"
    echo "[TraceOS] TraceOS background pixel fraction: $bg_fraction"
    if ! awk "BEGIN { exit !($accent_fraction > 0.0005) }"; then
        echo "[TraceOS] Screenshot is not showing the expected TraceOS accent pixels." >&2
        echo "$histogram" >&2
        exit 1
    fi
    if ! awk "BEGIN { exit !($bg_fraction > 0.005) }"; then
        echo "[TraceOS] Screenshot is missing the TraceOS desktop background signature." >&2
        echo "$histogram" >&2
        exit 1
    fi
    echo "[TraceOS] TraceOS visual signature detected in $page screenshot."

    assert_serial() {
        local marker="$1"
        local description="$2"
        if ! grep -q "$marker" "$STATE/serial-$page.log" 2>/dev/null; then
            echo "[TraceOS] Assertion failed: $description" >&2
            echo "[TraceOS] Serial tail:" >&2
            tail -n 220 "$STATE/serial-$page.log" >&2 || true
            exit 1
        fi
        echo "[TraceOS] Assertion passed: $description"
    }

    assert_serial "BOOT_USERNAME=traceos" "the ISO boot command line requests username=traceos"
    assert_serial "LIVE_SESSION_USER=traceos" "the graphical session user is traceos"
    assert_serial "LIVE_SESSION_HOME=/home/traceos" "the graphical session home is /home/traceos"
    assert_serial "TRACEOS_XFCE_SESSION_RUNNING" "the TraceOS XFCE session is running"
    assert_serial "CONTROL_CENTRE_PROCESS_RUNNING" "the Control Centre process is running"
    assert_serial "CONTROL_CENTRE_READY" "the Control Centre readiness marker was observed"

    rm -f "$ppm"
    if [[ "$keep_alive" != "true" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        unset QEMU_PID
    fi
}

# First prove the real desktop renders. Keep the same guest alive for one
# diagnostic interaction so the Dashboard remains the baseline gate.
capture_page dashboard true

# Diagnostic-only OSINT interaction. The shortcut is a normal user-facing
# Control Centre binding. This run records the full interaction chain without
# making page recognition a CI gate yet.
osint_ppm="$OUT/traceos-osint.ppm"
osint_png="$OUT/traceos-osint.png"
osint_immediate_ppm="$OUT/traceos-osint-immediate.ppm"
osint_immediate_png="$OUT/traceos-osint-immediate.png"
monitor="$STATE/monitor-dashboard.sock"
serial_log="$STATE/serial-dashboard.log"
osint_matrix="$OUT/traceos-osint-matrix.txt"

hmp_command "$monitor" "sendkey ctrl-shift-o" "$STATE/monitor-osint-sendkey.log"
hmp_sendkey_accepted="yes"

# Capture an immediate framebuffer so a later unchanged frame cannot be
# confused with a slow screendump or a transient transition.
capture_screendump "$monitor" "$osint_immediate_ppm" "$STATE/monitor-osint-immediate-screendump.log"
convert "$osint_immediate_ppm" -resize 1280x720 -strip "$osint_immediate_png"
identify "$osint_immediate_png"
test -s "$osint_immediate_png"

shortcut_received="no"
callback_entered="no"
callback_completed="no"
callback_exception="no"
page_rendered="no"

# Poll guest-side serial diagnostics with a bounded deadline. No arbitrary
# long sleep is used as the interaction proof.
for _ in $(seq 1 20); do
    if grep -Fq "UI_DIAG" "$serial_log" 2>/dev/null; then
        if grep -Fq "stage=shortcut-received" "$serial_log"; then shortcut_received="yes"; fi
        if grep -Fq "stage=callback-entered" "$serial_log"; then callback_entered="yes"; fi
        if grep -Fq "stage=callback-complete" "$serial_log"; then callback_completed="yes"; fi
        if grep -Fq "stage=callback-exception" "$serial_log"; then callback_exception="yes"; fi
        if grep -Fq "stage=osint-page-rendered" "$serial_log"; then page_rendered="yes"; fi
        if [[ "$page_rendered" == "yes" || "$callback_exception" == "yes" ]]; then
            break
        fi
    fi
    sleep 1
done

# Take the final framebuffer after observable guest evidence, or after the
# bounded diagnostic deadline if no guest evidence arrived.
capture_screendump "$monitor" "$osint_ppm" "$STATE/monitor-osint-screendump.log"
convert "$osint_ppm" -resize 1280x720 -strip "$osint_png"
identify "$osint_png"
test -s "$osint_png"

dashboard_png="$OUT/traceos-dashboard.png"
dashboard_hash="$(sha256sum "$dashboard_png" | awk '{print $1}')"
osint_immediate_hash="$(sha256sum "$osint_immediate_png" | awk '{print $1}')"
osint_hash="$(sha256sum "$osint_png" | awk '{print $1}')"

pixel_diff_immediate="$(compare -metric AE "$dashboard_png" "$osint_immediate_png" null: 2>&1 || true)"
pixel_diff_final="$(compare -metric AE "$dashboard_png" "$osint_png" null: 2>&1 || true)"
pixel_diff_transition="$(compare -metric AE "$osint_immediate_png" "$osint_png" null: 2>&1 || true)"

{
    echo "HMP_SENDKEY_ACCEPTED=$hmp_sendkey_accepted"
    echo "TK_EVENT_RECEIVED=$shortcut_received"
    echo "CALLBACK_ENTERED=$callback_entered"
    echo "CALLBACK_COMPLETED=$callback_completed"
    echo "CALLBACK_EXCEPTION=$callback_exception"
    echo "OSINT_PAGE_RENDERED=$page_rendered"
    echo "DASHBOARD_SHA256=$dashboard_hash"
    echo "OSINT_IMMEDIATE_SHA256=$osint_immediate_hash"
    echo "OSINT_FINAL_SHA256=$osint_hash"
    echo "PIXEL_DIFF_DASHBOARD_VS_IMMEDIATE_AE=$pixel_diff_immediate"
    echo "PIXEL_DIFF_DASHBOARD_VS_FINAL_AE=$pixel_diff_final"
    echo "PIXEL_DIFF_IMMEDIATE_VS_FINAL_AE=$pixel_diff_transition"
    if [[ "$pixel_diff_final" == "0" ]]; then
        echo "SCREENSHOT_CHANGED=no"
    else
        echo "SCREENSHOT_CHANGED=yes"
    fi
    echo "FOCUS_AND_ACTIVE_WINDOW_FROM_SHORTCUT_EVENT="
    grep -F "stage=shortcut-received" "$serial_log" 2>/dev/null | tail -n 1 || true
} >"$osint_matrix"

echo "[TraceOS] OSINT diagnostic matrix:"
cat "$osint_matrix"

# Keep the interaction page diagnostic-only in this batch. A later batch may
# promote page-specific recognition to a hard gate once this chain is proved.
spread="$(convert "$osint_png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
echo "[TraceOS] OSINT final framebuffer standard deviation: $spread"
if ! awk "BEGIN { exit !($spread > 0.02) }"; then
    echo "[TraceOS] OSINT diagnostic screenshot is blank/static." >&2
    tail -n 220 "$serial_log" >&2 || true
    exit 1
fi

echo "[TraceOS] OSINT diagnostic screenshot captured (page recognition is not yet a CI gate)."

rm -f "$OUT"/*.ppm

kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID

echo "[TraceOS] QEMU screenshots and diagnostics ready:"
find "$OUT" -maxdepth 1 -type f \( -name '*.png' -o -name '*.cfg' -o -name '*.log' -o -name '*.txt' \) -print -exec ls -lh {} +
