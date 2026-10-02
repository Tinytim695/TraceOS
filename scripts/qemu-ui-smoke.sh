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
}
trap cleanup EXIT

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

    python3 - "$monitor" "$ppm" <<'PY'
import socket
import sys
import time

monitor, ppm = sys.argv[1], sys.argv[2]

for _ in range(15):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(monitor)
        s.sendall(b"screendump " + ppm.encode() + b"\n")
        time.sleep(2)
        s.close()
        break
    except OSError:
        time.sleep(1)
else:
    raise SystemExit("Unable to connect to QEMU monitor")
PY

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
# Control Centre binding; this first run records the resulting real-ISO
# screenshot without making page recognition a CI gate yet.
osint_ppm="$OUT/traceos-osint.ppm"
osint_png="$OUT/traceos-osint.png"
python3 - "$STATE/monitor-dashboard.sock" "$STATE/monitor-osint.log" <<'PY'
import socket
import sys
import time

monitor, log_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(monitor)
s.sendall(b"sendkey ctrl-shift-o\n")
time.sleep(1)
try:
    response = s.recv(4096).decode("utf-8", "replace")
except OSError as exc:
    response = f"monitor recv failed: {exc}\n"
s.close()
open(log_path, "w", encoding="utf-8").write(response)
print(response, end="")
PY

sleep 3
python3 - "$STATE/monitor-dashboard.sock" "$osint_ppm" <<'PY'
import socket
import sys
import time

monitor, ppm = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(monitor)
s.sendall(b"screendump " + ppm.encode() + b"\n")
time.sleep(2)
s.close()
PY

test -s "$osint_ppm"
convert "$osint_ppm" -resize 1280x720 -strip "$osint_png"
identify "$osint_png"
test -s "$osint_png"
spread="$(convert "$osint_png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
echo "[TraceOS] OSINT diagnostic screenshot framebuffer standard deviation: $spread"
if ! awk "BEGIN { exit !($spread > 0.02) }"; then
    echo "[TraceOS] OSINT diagnostic screenshot is blank/static." >&2
    tail -n 220 "$STATE/serial-dashboard.log" >&2 || true
    exit 1
fi
echo "[TraceOS] OSINT diagnostic screenshot captured (page recognition is not yet a CI gate)."

kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID

echo "[TraceOS] QEMU screenshots ready:"
find "$OUT" -maxdepth 1 -type f -name '*.png' -print -exec ls -lh {} +
