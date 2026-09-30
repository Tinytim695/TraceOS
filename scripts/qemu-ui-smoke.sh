#!/usr/bin/env bash
set -euo pipefail

ISO="${1:-live-image-amd64.hybrid.iso}"
OUT="${2:-traceos-ui-screenshots}"
STATE="${3:-traceos-ui}"

test -s "$ISO"
rm -rf "$OUT" "$STATE"
mkdir -p "$OUT" "$STATE"

cleanup() {
    if [[ -n "${QEMU_PID:-}" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

xorriso -osirrox on -indev "$ISO" -extract /live/vmlinuz "$STATE/vmlinuz"
xorriso -osirrox on -indev "$ISO" -extract /live/initrd.img "$STATE/initrd.img"
test -s "$STATE/vmlinuz"
test -s "$STATE/initrd.img"

capture_page() {
    local page="$1"
    local monitor="$STATE/monitor-$page.sock"
    local vnc_socket="$STATE/vnc-$page.sock"
    local ppm="$OUT/traceos-$page.ppm"
    local png="$OUT/traceos-$page.png"
    rm -f "$monitor" "$vnc_socket" "$ppm" "$png"

    echo "[TraceOS] QEMU graphical page: $page"

    qemu-system-x86_64 \
        -accel tcg,thread=multi \
        -m 3072 \
        -smp 2 \
        -vga std \
        -nic none \
        -drive "file=$ISO,media=cdrom,readonly=on,format=raw" \
        -kernel "$STATE/vmlinuz" \
        -initrd "$STATE/initrd.img" \
        -append "boot=live components username=traceos hostname=traceos traceos-qemu-page=$page" \
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
        sleep 1
    done
    test -S "$monitor"

    # Live-boot + LightDM + XFCE + TraceOS autostart needs time under TCG.
    sleep 55

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

    # A real rendered UI should have measurable pixel variation.
    spread="$(convert "$png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
    echo "[TraceOS] $page framebuffer standard deviation: $spread"
    awk "BEGIN { exit !($spread > 0.02) }"

    rm -f "$ppm"
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
    unset QEMU_PID
}

capture_page dashboard
capture_page osint
capture_page shade

echo "[TraceOS] QEMU screenshots ready:"
find "$OUT" -maxdepth 1 -type f -name '*.png' -print -exec ls -lh {} \;
