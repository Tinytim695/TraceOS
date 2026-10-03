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

# Diagnostic-only New Case GUI interaction. This uses the normal visible Control Centre
# shortcut/button path and never calls CaseStore.create() outside the GUI process.
monitor="$STATE/monitor-dashboard.sock"
serial_log="$STATE/serial-dashboard.log"
new_case_matrix="$OUT/traceos-new-case-matrix.txt"
new_case_dialog_ppm="$OUT/traceos-new-case-dialog.ppm"
new_case_dialog_png="$OUT/traceos-new-case-dialog.png"
new_case_filled_ppm="$OUT/traceos-new-case-filled.ppm"
new_case_filled_png="$OUT/traceos-new-case-filled.png"
new_case_final_ppm="$OUT/traceos-new-case-final.ppm"
new_case_final_png="$OUT/traceos-new-case-final.png"

wait_for_serial() {
    local needle="$1"
    local timeout_seconds="$2"
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        if grep -Fq "$needle" "$serial_log" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

extract_field() {
    local line="$1"
    local field="$2"
    printf '%s\n' "$line" | tr ' ' '\n' | sed -n "s/^\${field}=//p" | tail -n 1
}

identity_line=""
if wait_for_serial "stage=CONTROL_CENTRE_SESSION_READY" 45; then
    identity_line="$(grep -F "stage=CONTROL_CENTRE_SESSION_READY" "$serial_log" | tail -n 1)"
fi

gui_nonce=""
gui_pid=""
gui_uid=""
if [[ -n "$identity_line" ]]; then
    gui_nonce="$(extract_field "$identity_line" nonce)"
    gui_pid="$(extract_field "$identity_line" pid)"
    gui_uid="$(extract_field "$identity_line" uid)"
fi

collector_ready="no"
if grep -Fq "QEMU_UI_DIAG_READY" "$serial_log" 2>/dev/null; then
    collector_ready="yes"
fi

hmp_new_case="yes"
if ! hmp_command "$monitor" "sendkey ctrl-shift-n" "$STATE/monitor-new-case-sendkey.log"; then
    hmp_new_case="no"
fi

attempt=""
if [[ -n "$gui_nonce" && -n "$gui_pid" ]]; then
    attempt="$(extract_field "$(grep -F "stage=NEW_CASE_INPUT_RECEIVED" "$serial_log" 2>/dev/null | tail -n 1 || true)" attempt)"
fi
[[ -n "$attempt" ]] || attempt="1"

marker_line() {
    local stage="$1"
    grep -F "stage=$stage" "$serial_log" 2>/dev/null \
        | grep -F "nonce=$gui_nonce" \
        | grep -F "pid=$gui_pid" \
        | grep -F "attempt=$attempt" \
        | tail -n 1 || true
}

input_received="no"
dialog_opened="no"
callback_entered="no"
case_created="no"
state_verified="no"
header_refreshed="no"
failed="no"
case_id=""
probe_line=""
probe_result="UNKNOWN"

for _ in $(seq 1 30); do
    [[ -n "$(marker_line "NEW_CASE_INPUT_RECEIVED")" ]] && input_received="yes"
    [[ -n "$(marker_line "NEW_CASE_DIALOG_OPENED")" ]] && dialog_opened="yes"
    if [[ -n "$(marker_line "NEW_CASE_FAILED")" ]]; then
        failed="yes"
        break
    fi
    [[ "$dialog_opened" == "yes" ]] && break
    sleep 1
done

if [[ "$dialog_opened" == "yes" ]]; then
    capture_screendump "$monitor" "$new_case_dialog_ppm" "$STATE/monitor-new-case-dialog-screendump.log"
    convert "$new_case_dialog_ppm" -resize 1280x720 -strip "$new_case_dialog_png"
    identify "$new_case_dialog_png"

    title_index=0
    for key in q e m u c a s e; do
        title_index=$((title_index + 1))
        hmp_command "$monitor" "sendkey $key" "$STATE/monitor-new-case-key-$title_index.log"
    done

    capture_screendump "$monitor" "$new_case_filled_ppm" "$STATE/monitor-new-case-filled-screendump.log"
    convert "$new_case_filled_ppm" -resize 1280x720 -strip "$new_case_filled_png"
    identify "$new_case_filled_png"

    # Return while the real title Entry has focus. This invokes the same nested
    # Create callback used by the visible CREATE CASE button.
    hmp_command "$monitor" "sendkey ret" "$STATE/monitor-new-case-submit.log" || true
else
    : >"$STATE/monitor-new-case-key-skipped.log"
    : >"$STATE/monitor-new-case-submit-skipped.log"
fi

for _ in $(seq 1 45); do
    [[ -n "$(marker_line "NEW_CASE_CREATE_CALLBACK_ENTERED")" ]] && callback_entered="yes"
    created_line="$(marker_line "NEW_CASE_CREATED")"
    if [[ -n "$created_line" ]]; then
        case_created="yes"
        case_id="$(extract_field "$created_line" case_id)"
    fi
    [[ -n "$(marker_line "NEW_CASE_STATE_VERIFIED")" ]] && state_verified="yes"
    [[ -n "$(marker_line "NEW_CASE_HEADER_REFRESHED")" ]] && header_refreshed="yes"
    if [[ -n "$(marker_line "NEW_CASE_FAILED")" ]]; then
        failed="yes"
        break
    fi
    if [[ -n "$case_id" ]]; then
        probe_line="$(grep -F "stage=NEW_CASE_STATE_PROBE" "$serial_log" 2>/dev/null \
            | grep -F "nonce=$gui_nonce" \
            | grep -F "pid=$gui_pid" \
            | grep -F "attempt=$attempt" \
            | grep -F "case_id=$case_id" \
            | tail -n 1 || true)"
        if [[ -n "$probe_line" ]]; then
            probe_result="$(extract_field "$probe_line" result)"
        fi
    fi
    if [[ "$callback_entered" == "yes" && "$case_created" == "yes" && "$state_verified" == "yes" && "$header_refreshed" == "yes" && "$probe_result" == "PASS" ]]; then
        break
    fi
    sleep 1
done

capture_screendump "$monitor" "$new_case_final_ppm" "$STATE/monitor-new-case-final-screendump.log"
convert "$new_case_final_ppm" -resize 1280x720 -strip "$new_case_final_png"
identify "$new_case_final_png"
test -s "$new_case_final_png"

dashboard_png="$OUT/traceos-dashboard.png"
dashboard_hash="$(sha256sum "$dashboard_png" | awk '{print $1}')"
dialog_hash="$(sha256sum "$new_case_dialog_png" 2>/dev/null | awk '{print $1}' || true)"
filled_hash="$(sha256sum "\${OUT}/traceos-new-case-filled.png" 2>/dev/null | awk '{print $1}' || true)"
final_hash="$(sha256sum "$new_case_final_png" | awk '{print $1}')"
pixel_diff_dashboard_final="$(compare -metric AE "$dashboard_png" "$new_case_final_png" null: 2>&1 || true)"
pixel_diff_dialog_filled="$(compare -metric AE "$new_case_dialog_png" "\${OUT}/traceos-new-case-filled.png" null: 2>&1 || true)"
pixel_diff_filled_final="$(compare -metric AE "\${OUT}/traceos-new-case-filled.png" "$new_case_final_png" null: 2>&1 || true)"

if [[ -n "$case_id" ]]; then
    header_marker="$(marker_line "NEW_CASE_HEADER_REFRESHED")"
    header_case_id="$(extract_field "$header_marker" case_id)"
    header_prefix="$(extract_field "$header_marker" id_prefix)"
    if [[ "$header_case_id" == "$case_id" && "$header_prefix" == "$case_id"* ]]; then
        header_widget_match="yes"
    else
        header_widget_match="no"
    fi
else
    header_widget_match="unknown"
fi

if [[ "$hmp_new_case" != "yes" ]]; then
    status="FAIL"
elif [[ "$failed" == "yes" ]]; then
    status="FAIL"
elif [[ "$collector_ready" != "yes" || -z "$gui_nonce" || -z "$gui_pid" ]]; then
    status="UNKNOWN"
elif [[ "$input_received" != "yes" || "$dialog_opened" != "yes" || "$callback_entered" != "yes" || "$case_created" != "yes" || "$state_verified" != "yes" || "$header_refreshed" != "yes" || "$probe_result" != "PASS" || "$header_widget_match" != "yes" ]]; then
    status="UNKNOWN"
else
    status="PASS"
fi

{
    echo "STATUS=$status"
    echo "HMP_NEW_CASE_ACCEPTED=$hmp_new_case"
    echo "COLLECTOR_READY=$collector_ready"
    echo "GUI_NONCE=\${gui_nonce:-unknown}"
    echo "GUI_PID=\${gui_pid:-unknown}"
    echo "GUI_UID=\${gui_uid:-unknown}"
    echo "ATTEMPT=$attempt"
    echo "NEW_CASE_INPUT_RECEIVED=$input_received"
    echo "NEW_CASE_DIALOG_OPENED=$dialog_opened"
    echo "NEW_CASE_CREATE_CALLBACK_ENTERED=$callback_entered"
    echo "NEW_CASE_CREATED=$case_created"
    echo "CASE_ID=\${case_id:-unknown}"
    echo "NEW_CASE_STATE_VERIFIED=$state_verified"
    echo "NEW_CASE_STATE_PROBE=$probe_result"
    echo "NEW_CASE_HEADER_REFRESHED=$header_refreshed"
    echo "HEADER_WIDGET_ID_PREFIX_MATCH=$header_widget_match"
    echo "DASHBOARD_SHA256=$dashboard_hash"
    echo "NEW_CASE_DIALOG_SHA256=$dialog_hash"
    echo "NEW_CASE_FILLED_SHA256=$filled_hash"
    echo "NEW_CASE_FINAL_SHA256=$final_hash"
    echo "PIXEL_DIFF_DASHBOARD_VS_FINAL_AE=$pixel_diff_dashboard_final"
    echo "PIXEL_DIFF_DIALOG_VS_FILLED_AE=$pixel_diff_dialog_filled"
    echo "PIXEL_DIFF_FILLED_VS_FINAL_AE=$pixel_diff_filled_final"
    if [[ "$pixel_diff_dashboard_final" == "0" ]]; then
        echo "SCREENSHOT_CHANGED=no"
    else
        echo "SCREENSHOT_CHANGED=yes"
    fi
    echo
    echo "NEW_CASE_MARKERS:"
    grep -F "stage=NEW_CASE_" "$serial_log" 2>/dev/null \
        | grep -F "nonce=$gui_nonce" \
        | grep -F "pid=$gui_pid" \
        | grep -F "attempt=$attempt" || true
    echo
    echo "STATE_PROBE:"
    grep -F "stage=NEW_CASE_STATE_PROBE" "$serial_log" 2>/dev/null \
        | grep -F "nonce=$gui_nonce" \
        | grep -F "pid=$gui_pid" \
        | grep -F "attempt=$attempt" || true
} >"$new_case_matrix"

echo "[TraceOS] New Case GUI diagnostic matrix:"
cat "$new_case_matrix"

rm -f "$OUT"/*.ppm

kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID

echo "[TraceOS] QEMU screenshots and diagnostics ready:"
find "$OUT" -maxdepth 1 -type f \( -name '*.png' -o -name '*.cfg' -o -name '*.log' -o -name '*.txt' \) -print -exec ls -lh {} +
