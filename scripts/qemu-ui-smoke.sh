#!/usr/bin/env bash
set -euo pipefail

ISO="${1:-live-image-amd64.hybrid.iso}"
OUT="${2:-traceos-ui-screenshots}"
STATE="${3:-traceos-ui}"

if [[ "${TRACEOS_QEMU_UI_PARSER_TEST:-0}" != "1" ]]; then
    test -s "$ISO"
    rm -rf "$OUT" "$STATE"
    mkdir -p "$OUT" "$STATE"
fi

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

# Validate generated bootloader payloads. Parser-fixture mode never reaches
# these calls, so it does not need an ISO. Extraction failures are not ignored
# on the real graphical path: both configs must come out of the ISO.
assert_generated_grub() {
    local grub_cfg="$1"
    local failsafe_block linux_line initrd_line first_entry default_line
    local line path boot_text

    if [[ ! -s "$grub_cfg" ]]; then
        echo "[TraceOS] Generated GRUB config is missing or empty." >&2
        return 1
    fi
    if ! grep -Eq '(^|[[:space:]])username=traceos([[:space:]]|$)' "$grub_cfg"; then
        echo "[TraceOS] Generated GRUB config is missing username=traceos." >&2
        return 1
    fi
    if grep -Eq '@(KERNEL_LIVE|INITRD_LIVE|APPEND_LIVE(_FAILSAFE)?)@' "$grub_cfg"; then
        echo "[TraceOS] Generated GRUB config contains unresolved live-build placeholders." >&2
        return 1
    fi

    failsafe_block="$(awk '
        $0 ~ /^menuentry "TraceOS Failsafe \(Amnesic\)"/ { capture = 1 }
        capture { print }
        capture && /^}/ { exit }
    ' "$grub_cfg")"
    linux_line="$(printf '%s\n' "$failsafe_block" | grep -E '^[[:space:]]*linux[[:space:]]' | head -n 1 || true)"
    initrd_line="$(printf '%s\n' "$failsafe_block" | grep -E '^[[:space:]]*initrd[[:space:]]' | head -n 1 || true)"
    if [[ -z "$linux_line" || -z "$initrd_line" ]]; then
        echo "[TraceOS] Generated GRUB failsafe entry is missing resolved paths or expected arguments." >&2
        return 1
    fi
    if ! printf '%s\n' "$linux_line" | grep -Eq '(^|[[:space:]])nopersistence([[:space:]]|$)'; then
        echo "[TraceOS] Generated GRUB failsafe entry is missing resolved paths or expected arguments." >&2
        return 1
    fi
    if ! printf '%s\n' "$linux_line" | grep -Eq '(^|[[:space:]])nomodeset([[:space:]]|$)'; then
        echo "[TraceOS] Generated GRUB failsafe entry is missing resolved paths or expected arguments." >&2
        return 1
    fi

    boot_text="$(grep -E '^[[:space:]]*(linux|initrd)[[:space:]]+' "$grub_cfg" || true)"
    if [[ -z "$boot_text" ]]; then
        echo "[TraceOS] Generated GRUB config has an unresolved kernel or initrd path." >&2
        return 1
    fi
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        path="$(printf '%s\n' "$line" | awk '{ print $2 }')"
        case "$path" in
            /live/*) ;;
            *)
                echo "[TraceOS] Generated GRUB config has an unresolved kernel or initrd path." >&2
                return 1
                ;;
        esac
    done <<EOF
$boot_text
EOF

    default_line="$(grep -E '^set default=' "$grub_cfg" | tail -n 1 || true)"
    first_entry="$(grep -E '^menuentry ' "$grub_cfg" | head -n 1 || true)"
    if [[ "$default_line" != "set default=0" ]] || [[ "$first_entry" != 'menuentry "TraceOS Amnesic (no persistent storage)" {' ]]; then
        echo "[TraceOS] Generated GRUB default selection could not be verified." >&2
        return 1
    fi
}


assert_ui_matrix_status() {
    local new_case_status="$1"
    local image_status="$2"

    if [[ "$new_case_status" != "PASS" ]]; then
        echo "[TraceOS] QEMU New Case matrix is $new_case_status; GUI smoke cannot pass." >&2
        return 1
    fi
    if [[ "$image_status" != "yes" ]]; then
        echo "[TraceOS] QEMU image OSINT matrix did not reach a verified synthetic result." >&2
        return 1
    fi
    return 0
}


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
error_pattern = re.compile(r"(?im)^\s*(?:Error:|unknown command|invalid parameter|command .* failed|failed to .*|could not .*|HMP .*error)")
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
        -fw_cfg name=opt/traceos/ui-image-e2e,string=1 \
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

    if [[ "$page" == "dashboard" ]]; then
        # The intended first screen is TraceOS Launcher, not the Control Centre.
        launcher_deadline=$((SECONDS + 600))
        while (( SECONDS < launcher_deadline )); do
            if grep -Fq "stage=TRACEOS_LAUNCHER_SESSION_READY" "$STATE/serial-$page.log" 2>/dev/null; then
                break
            fi
            if ! kill -0 "$QEMU_PID" 2>/dev/null; then
                echo "[TraceOS] QEMU exited before the TraceOS Launcher became ready." >&2
                tail -n 220 "$STATE/serial-$page.log" >&2 || true
                exit 1
            fi
            sleep 1
        done
        if ! grep -Fq "stage=TRACEOS_LAUNCHER_SESSION_READY" "$STATE/serial-$page.log" 2>/dev/null; then
            echo "[TraceOS] TraceOS Launcher readiness marker was not observed." >&2
            tail -n 220 "$STATE/serial-$page.log" >&2 || true
            exit 1
        fi
        launcher_ready_line="$(grep -m1 -F 'stage=TRACEOS_LAUNCHER_SESSION_READY' "$STATE/serial-$page.log")"
        launcher_nonce="$(extract_field "$launcher_ready_line" nonce)"
        if [[ -z "$launcher_nonce" ]]; then
            echo "[TraceOS] Launcher readiness record has no nonce; cannot correlate action evidence." >&2
            exit 1
        fi

        launcher_home_ppm="$OUT/traceos-launcher-home.ppm"
        launcher_home_png="$OUT/traceos-launcher-home.png"
        capture_screendump "$monitor" "$launcher_home_ppm" "$STATE/monitor-launcher-home-screendump.log"
        convert "$launcher_home_ppm" -resize 1280x720 -strip "$launcher_home_png"
        identify "$launcher_home_png"
        test -s "$launcher_home_png"
        launcher_spread="$(convert "$launcher_home_png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
        launcher_accent="$(convert "$launcher_home_png" -fuzz 10% -fill white -opaque "#72F1E8" -fill black +opaque white -format "%[fx:mean]" info:)"
        launcher_bg="$(convert "$launcher_home_png" -fuzz 10% -fill white -opaque "#050811" -fill black +opaque white -format "%[fx:mean]" info:)"
        if ! awk "BEGIN { exit !($launcher_spread > 0.02 && $launcher_accent > 0.0005 && $launcher_bg > 0.005) }"; then
            echo "[TraceOS] Launcher home screenshot is blank or missing the TraceOS visual signature." >&2
            exit 1
        fi
        echo "[TraceOS] Branded TraceOS Launcher home screen is visible."

        # HMP mouse_move is a relative event, even when a USB tablet exists.
        # Do not pass screen pixels or 0..32767 tablet coordinates to it.
        # The real primary button receives focus before SESSION_READY; activate
        # it through the guest keyboard so this smoke test proves the real
        # Tk callback path without pretending to verify pointer delivery.
        echo "[TraceOS] Activating the focused Control Centre button via guest keyboard."
        hmp_command "$monitor" "sendkey ret" "$STATE/monitor-launcher-control-centre-keyboard.log"
        sleep 0.2
        action_deadline=$((SECONDS + 45))
        while (( SECONDS < action_deadline )); do
            if launcher_action_seen "$STATE/serial-$page.log" "$launcher_nonce"; then
                break
            fi
            sleep 1
        done
        if ! launcher_action_seen "$STATE/serial-$page.log" "$launcher_nonce"; then
            echo "[TraceOS] Launcher mouse activation did not produce a correlated Control Centre action for nonce=$launcher_nonce." >&2
            if grep -Fq 'stage=TRACEOS_LAUNCHER_RAW_CLICK' "$STATE/serial-$page.log"; then
                echo "[TraceOS] Raw launcher click telemetry was observed." >&2
            else
                echo "[TraceOS] No raw launcher click telemetry was observed." >&2
            fi
            failure_ppm="$OUT/traceos-launcher-control-centre-failure.ppm"
            failure_png="$OUT/traceos-launcher-control-centre-failure.png"
            capture_screendump "$monitor" "$failure_ppm" "$STATE/monitor-launcher-control-centre-failure-screendump.log" || true
            if [[ -s "$failure_ppm" ]]; then
                convert "$failure_ppm" -strip "$failure_png" || true
                rm -f "$failure_ppm"
            fi
            tail -n 220 "$STATE/serial-$page.log" >&2 || true
            exit 1
        fi
    fi

    # TCG is slow and shared CI runners vary. Wait for the real Control Centre
    # session marker instead of burning a fixed five minutes, but retain a
    # 300-second hard ceiling before declaring the graphical desktop absent.
    readiness_deadline=$((SECONDS + 300))
    while (( SECONDS < readiness_deadline )); do
        if grep -Fq "stage=CONTROL_CENTRE_SESSION_READY" "$STATE/serial-$page.log" 2>/dev/null; then
            echo "[TraceOS] Control Centre session readiness observed."
            break
        fi
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "[TraceOS] QEMU exited before Control Centre session readiness." >&2
            tail -n 220 "$STATE/serial-$page.log" >&2 || true
            exit 1
        fi
        sleep 1
    done
    if ! grep -Fq "stage=CONTROL_CENTRE_SESSION_READY" "$STATE/serial-$page.log" 2>/dev/null; then
        echo "[TraceOS] Control Centre session readiness marker was not observed before deadline." >&2
        tail -n 220 "$STATE/serial-$page.log" >&2 || true
        exit 1
    fi

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
    # This diagnostic is a boot-time snapshot, before the launcher action. It
    # cannot reliably prove the Control Centre state after the launcher starts it.
    assert_serial "stage=CONTROL_CENTRE_SESSION_READY" "the Control Centre session readiness marker was observed"

    rm -f "$ppm"
    if [[ "$keep_alive" != "true" ]]; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
        unset QEMU_PID
    fi
}


extract_field() {
    local line="$1"
    local field="$2"
    local value
    local cr
    value="$(printf '%s\n' "$line" | tr ' ' '\n' | sed -n "s/^${field}=//p" | tail -n 1)"
    cr="$(printf '\r')"
    printf '%s\n' "${value%$cr}"
}



launcher_action_seen() {
    local serial_log="$1"
    local expected_nonce="$2"
    grep -F 'stage=TRACEOS_LAUNCHER_ACTION_INVOKED' "$serial_log" 2>/dev/null |
        grep -F 'action=control-centre' |
        grep -F "nonce=$expected_nonce" >/dev/null
}

# The Applications menu against the Control Centre baseline measures 24,991
# changed pixels in the 300x500 popup crop. A threshold of 25,000 rejected
# that open menu. Cursor-only noise in this crop stays far below 20,000.
popup_region_diff_passes() {
    local changed_pixels="$1"
    [[ "$changed_pixels" =~ ^[0-9]+$ ]] && (( changed_pixels > 20000 ))
}

if [[ "${TRACEOS_QEMU_UI_PARSER_TEST:-0}" == "1" ]]; then
    test_case_id="01234567-89ab-cdef-0123-456789abcdef"
    matching="case_id=${test_case_id} id_prefix=01234567"
    wrong_uuid="case_id=11234567-89ab-cdef-0123-456789abcdef id_prefix=01234567"
    wrong_prefix="case_id=${test_case_id} id_prefix=11234567"
    short_prefix="case_id=${test_case_id} id_prefix=0123456"

    header_match() {
        local header_case_id="$1"
        local header_prefix="$2"
        [[ "$header_case_id" == "$test_case_id" &&
           ${#header_prefix} -eq 8 &&
           "$header_prefix" == "${test_case_id:0:8}" ]]
    }

    [[ "$(extract_field "$matching" case_id)" == "$test_case_id" ]]
    [[ "$(extract_field "$matching" id_prefix)" == "01234567" ]]
    header_match "$test_case_id" "01234567"
    ! header_match "$(extract_field "$wrong_uuid" case_id)" "$(extract_field "$wrong_uuid" id_prefix)"
    ! header_match "$test_case_id" "$(extract_field "$wrong_prefix" id_prefix)"
    ! header_match "$test_case_id" "$(extract_field "$short_prefix" id_prefix)"

    matching_cr="$(printf 'case_id=%s id_prefix=01234567\r' "$test_case_id")"
    [[ "$(extract_field "$matching_cr" case_id)" == "$test_case_id" ]]
    [[ "$(extract_field "$matching_cr" id_prefix)" == "01234567" ]]

    # Action evidence must correlate stage, action and the current launcher nonce
    # on one record. Independent grep hits and stale nonces must not pass.
    action_log="$(mktemp)"
    printf '%s\n' \
        '[TraceOS] UI_DIAG stage=TRACEOS_LAUNCHER_ACTION_INVOKED nonce=stale action=control-centre' \
        '[TraceOS] UI_DIAG stage=TRACEOS_LAUNCHER_ACTION_INVOKED nonce=fixture action=browser' \
        '[TraceOS] UI_DIAG stage=TRACEOS_LAUNCHER_SESSION_READY nonce=fixture page=home' >"$action_log"
    if launcher_action_seen "$action_log" fixture; then
        echo "[TraceOS] Correlation fixture accepted split/stale action records." >&2
        exit 1
    fi
    printf '%s\n' '[TraceOS] UI_DIAG stage=TRACEOS_LAUNCHER_ACTION_INVOKED nonce=fixture action=control-centre' >>"$action_log"
    launcher_action_seen "$action_log" fixture
    rm -f "$action_log"

    # Regression guard: a visible popup at 24,991 changed pixels was rejected
    # by the old 25,000 threshold even though the crop showed the menu.
    popup_region_diff_passes 24991
    if popup_region_diff_passes 20000; then
        echo "[TraceOS] Popup fixture accepted the exact threshold boundary." >&2
        exit 1
    fi
    if popup_region_diff_passes not-a-number; then
        echo "[TraceOS] Popup fixture accepted a non-numeric diff." >&2
        exit 1
    fi

    # Synthetic generated GRUB configs. These do not require an ISO and must
    # reject unresolved placeholders, a bad failsafe entry, unresolved
    # kernel/initrd paths, and a default that is not the amnesic menu.
    fixture_dir="$(mktemp -d)"
    trap 'rm -rf "$fixture_dir"; cleanup' EXIT
    valid_grub="$fixture_dir/valid.cfg"
    cat >"$valid_grub" <<'EOF'
set timeout=8
set default=0
source /boot/grub/config.cfg

menuentry "TraceOS Amnesic (no persistent storage)" {
    linux /live/vmlinuz boot=live components username=traceos hostname=traceos nopersistence splash
    initrd /live/initrd.img
}

menuentry "TraceOS Persistent" {
    linux /live/vmlinuz boot=live components username=traceos hostname=traceos persistence splash
    initrd /live/initrd.img
}

menuentry "TraceOS Failsafe (Amnesic)" {
    linux /live/vmlinuz boot=live components username=traceos hostname=traceos nomodeset nopersistence
    initrd /live/initrd.img
}
EOF
    assert_generated_grub "$valid_grub"

    reject_grub() {
        local label="$1"
        local cfg="$2"
        if assert_generated_grub "$cfg" 2>/dev/null; then
            echo "[TraceOS] GRUB fixture unexpectedly accepted: $label" >&2
            exit 1
        fi
    }

    cp "$valid_grub" "$fixture_dir/placeholder.cfg"
    printf '\nlinux @KERNEL_LIVE@ @APPEND_LIVE_FAILSAFE@ nopersistence\ninitrd @INITRD_LIVE@\n' >>"$fixture_dir/placeholder.cfg"
    reject_grub "unresolved placeholders" "$fixture_dir/placeholder.cfg"

    sed 's/nomodeset nopersistence/nopersistence/' "$valid_grub" >"$fixture_dir/no-nomodeset.cfg"
    reject_grub "failsafe missing nomodeset" "$fixture_dir/no-nomodeset.cfg"

    sed 's#nomodeset nopersistence#nomodeset persistence#' "$valid_grub" >"$fixture_dir/no-nopersistence.cfg"
    reject_grub "failsafe missing nopersistence" "$fixture_dir/no-nopersistence.cfg"

    sed 's#linux /live/vmlinuz boot=live components username=traceos hostname=traceos nomodeset#linux vmlinuz boot=live components username=traceos hostname=traceos nomodeset#' \
        "$valid_grub" >"$fixture_dir/bad-kernel.cfg"
    reject_grub "unresolved failsafe kernel" "$fixture_dir/bad-kernel.cfg"

    sed 's#initrd /live/initrd.img#initrd /boot/initrd.img#' "$valid_grub" >"$fixture_dir/bad-initrd.cfg"
    reject_grub "unresolved initrd" "$fixture_dir/bad-initrd.cfg"

    sed 's/^set default=0$/set default=1/' "$valid_grub" >"$fixture_dir/bad-default.cfg"
    reject_grub "default is not amnesic" "$fixture_dir/bad-default.cfg"

    sed '0,/menuentry "TraceOS Amnesic (no persistent storage)"/s//menuentry "TraceOS Persistent"/' \
        "$valid_grub" >"$fixture_dir/reordered.cfg"
    reject_grub "first menuentry is not amnesic" "$fixture_dir/reordered.cfg"

    sed 's/username=traceos //g' "$valid_grub" >"$fixture_dir/no-user.cfg"
    reject_grub "missing username" "$fixture_dir/no-user.cfg"

    rm -rf "$fixture_dir"

    # The GUI release gate must reject UNKNOWN as well as FAIL. Keep these
    # fixtures here so the logic is checked even when no ISO has been built.
    assert_ui_matrix_status PASS yes
    if assert_ui_matrix_status UNKNOWN yes 2>/dev/null; then
        echo "[TraceOS] Matrix gate accepted UNKNOWN New Case status." >&2
        exit 1
    fi
    if assert_ui_matrix_status FAIL yes 2>/dev/null; then
        echo "[TraceOS] Matrix gate accepted failed New Case status." >&2
        exit 1
    fi
    if assert_ui_matrix_status PASS no 2>/dev/null; then
        echo "[TraceOS] Matrix gate accepted missing image result." >&2
        exit 1
    fi
    # Captured QEMU run 39575885016: the Applications menu was visibly open
    # and the popup crop differed by exactly 24,991 pixels.
    popup_region_diff_passes 24991
    if popup_region_diff_passes 20000; then
        echo "[TraceOS] Popup fixture accepted the exact threshold boundary." >&2
        exit 1
    fi
    if popup_region_diff_passes not-a-number; then
        echo "[TraceOS] Popup fixture accepted a non-numeric diff." >&2
        exit 1
    fi

    echo "[TraceOS] QEMU GUI parser fixtures: PASS"
    exit 0
fi

# Validate the actual bootloader payloads inside the ISO before spending five
# minutes on the graphical boot. The BIOS El Torito path is the path used by
# QEMU below, so it must carry the same live username as the GRUB path.
# Do not ignore extraction failure: a missing GRUB or ISOLINUX payload is a
# failed smoke test, not a warning.
extract_boot_config /isolinux/isolinux.cfg "$OUT/traceos-generated-isolinux.cfg"
extract_boot_config /boot/grub/grub.cfg "$OUT/traceos-generated-grub.cfg"

if ! grep -Eq '(^|[[:space:]])username=traceos([[:space:]]|$)' "$OUT/traceos-generated-isolinux.cfg"; then
    echo "[TraceOS] Generated ISOLINUX config is missing username=traceos." >&2
    exit 1
fi
assert_generated_grub "$OUT/traceos-generated-grub.cfg"

# Retain the wallpaper asset extracted from this exact ISO by the preceding
# final-squashfs validation step. This is compared with the guest runtime hash.
packaged_wallpaper_source="/tmp/traceos-root/usr/share/backgrounds/traceos/traceos-wallpaper.png"
packaged_wallpaper_png="$OUT/traceos-packaged-wallpaper.png"
test -s "$packaged_wallpaper_source"
cp "$packaged_wallpaper_source" "$packaged_wallpaper_png"
packaged_wallpaper_dimensions="$(identify -format '%w %h' "$packaged_wallpaper_png")"
test "$packaged_wallpaper_dimensions" = "1920 1080"
packaged_wallpaper_sha256="$(sha256sum "$packaged_wallpaper_png" | awk '{print $1}')"
printf 'TRACEOS_PACKAGED_WALLPAPER_DIMENSIONS=%s\nTRACEOS_PACKAGED_WALLPAPER_SHA256=%s\n' \
    "$packaged_wallpaper_dimensions" "$packaged_wallpaper_sha256" >"$OUT/traceos-wallpaper-manifest.txt"
packaged_wallpaper_mean="$(convert "$packaged_wallpaper_png" -format '%[fx:mean]' info:)"
packaged_wallpaper_center="$(convert "$packaged_wallpaper_png" -gravity center -crop 640x480+0+0 +repage -format '%[fx:mean]' info:)"
if ! awk "BEGIN { exit !($packaged_wallpaper_mean > 0.10) }"; then
    echo "[TraceOS] Packaged wallpaper is too dark (mean=$packaged_wallpaper_mean)." >&2
    exit 1
fi
if ! awk "BEGIN { exit !($packaged_wallpaper_center > 0.18) }"; then
    echo "[TraceOS] Packaged wallpaper centre is too dark (mean=$packaged_wallpaper_center)." >&2
    exit 1
fi
echo "[TraceOS] Packaged wallpaper mean luminance: $packaged_wallpaper_mean centre: $packaged_wallpaper_center"

# First prove the real desktop renders. Keep the same guest alive for one
# diagnostic interaction so the Dashboard remains the baseline gate.
capture_page dashboard true

# Page shortcuts run after the Applications menu is closed. The pointer click
# below is the one that let Ctrl+Shift+W through on the last green run.
monitor="$STATE/monitor-dashboard.sock"
serial_log="$STATE/serial-dashboard.log"
workspace_matrix="$OUT/traceos-workspace-ui-matrix.txt"
: >"$workspace_matrix"

capture_workspace_page() {
    local page="$1"
    local key="$2"
    local marker="$3"
    local label="$4"
    local allow_same="${5:-no}"
    local ppm="$OUT/traceos-$page.ppm"
    local png="$OUT/traceos-$page.png"
    local before rendered page_pixel_diff spread attempt

    if [[ -z "${gui_nonce:-}" || -z "${gui_pid:-}" ]]; then
        echo "[TraceOS] $page capture has no Control Centre nonce or pid." >&2
        return 1
    fi
    before="$(wc -l < "$serial_log" | tr -d ' ')"
    hmp_command "$monitor" "sendkey ctrl-shift-$key" "$STATE/monitor-$page-sendkey.log"

    rendered="no"
    for _ in $(seq 1 20); do
        if tail -n +"$((before + 1))" "$serial_log" 2>/dev/null \
            | grep -F "stage=$marker" \
            | grep -F "nonce=$gui_nonce" \
            | grep -Fq "pid=$gui_pid"; then
            rendered="yes"
            break
        fi
        sleep 1
    done
    if [[ "$rendered" != "yes" ]]; then
        echo "[TraceOS] $page page did not report a fresh GUI render for nonce=$gui_nonce pid=$gui_pid." >&2
        if tail -n +"$((before + 1))" "$serial_log" 2>/dev/null | grep -F "stage=PAGE_SHORTCUT_RECEIVED" | grep -F "nonce=$gui_nonce" | grep -Fq "pid=$gui_pid"; then
            echo "[TraceOS] The shortcut reached Control Centre, but $page did not finish drawing." >&2
        elif grep -F "stage=CONTROL_CENTRE_POINTER_FOCUS" "$serial_log" 2>/dev/null | grep -F "nonce=$gui_nonce" | grep -Fq "pid=$gui_pid"; then
            echo "[TraceOS] The click focused Control Centre, but the shortcut still did not arrive." >&2
        elif grep -F "stage=CONTROL_CENTRE_KEY" "$serial_log" 2>/dev/null | grep -F "nonce=$gui_nonce" | grep -Fq "pid=$gui_pid"; then
            echo "[TraceOS] A key reached Control Centre, but it was not the overview chord." >&2
        elif grep -F "stage=CONTROL_CENTRE_KEYBOARD_GRAB" "$serial_log" 2>/dev/null | grep -F "result=held" | grep -Fq "nonce=$gui_nonce"; then
            echo "[TraceOS] Control Centre held a global keyboard grab, but the shortcut still did not arrive." >&2
        elif grep -F "stage=CONTROL_CENTRE_KEYBOARD_GRAB" "$serial_log" 2>/dev/null | grep -F "result=failed" | grep -Fq "nonce=$gui_nonce"; then
            echo "[TraceOS] Control Centre could not grab the keyboard." >&2
        elif grep -F "stage=CONTROL_CENTRE_VIRT" "$serial_log" 2>/dev/null | grep -F "nonce=$gui_nonce" | grep -Fq "pid=$gui_pid"; then
            echo "[TraceOS] Control Centre decided this was not the screenshot guest." >&2
            grep -F "stage=CONTROL_CENTRE_VIRT" "$serial_log" | tail -n 3 >&2 || true
        else
            echo "[TraceOS] The shortcut never reached Control Centre, and the click did not focus it." >&2
        fi
        tail -n 80 "$serial_log" >&2 || true
        return 1
    fi

    page_pixel_diff=""
    spread=""
    for attempt in $(seq 1 8); do
        capture_screendump "$monitor" "$ppm" "$STATE/monitor-$page-screendump.log"
        convert "$ppm" -resize 1280x720 -strip "$png"
        identify "$png"
        test -s "$png"
        page_pixel_diff="$(compare -metric AE "$OUT/traceos-dashboard.png" "$png" null: 2>&1 || true)"
        spread="$(convert "$png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
        if [[ "$allow_same" == "yes" ]] && awk "BEGIN { exit !($spread > 0.02) }"; then
            break
        fi
        if [[ "$page_pixel_diff" =~ ^[0-9]+$ ]] && (( page_pixel_diff > 5000 )) && awk "BEGIN { exit !($spread > 0.02) }"; then
            break
        fi
        echo "[TraceOS] $page framebuffer not ready (attempt $attempt, changed pixels: ${page_pixel_diff:-unknown})." >&2
        sleep 1
    done
    if [[ "$allow_same" != "yes" ]] && { [[ ! "$page_pixel_diff" =~ ^[0-9]+$ ]] || (( page_pixel_diff <= 5000 )); }; then
        echo "[TraceOS] $page screenshot is indistinguishable from the Dashboard (changed pixels: ${page_pixel_diff:-unknown})." >&2
        return 1
    fi
    if ! awk "BEGIN { exit !($spread > 0.02) }"; then
        echo "[TraceOS] $page page screenshot is blank or static." >&2
        return 1
    fi
    echo "[TraceOS] $page differs from Dashboard across ${page_pixel_diff:-same} pixels."
    printf "%s_UI=PASS\n%s_SHA256=%s\n%s_DASHBOARD_PIXEL_DIFF=%s\n" "$label" "$label" "$(sha256sum "$png" | awk '{print $1}')" "$label" "${page_pixel_diff:-0}" >>"$workspace_matrix"
    echo "[TraceOS] $page workspace rendered and captured."
}

identity_line="$(grep -F 'stage=CONTROL_CENTRE_SESSION_READY' "$serial_log" | tail -n 1 || true)"
gui_nonce="$(extract_field "$identity_line" nonce)"
gui_pid="$(extract_field "$identity_line" pid)"
if [[ -z "$gui_nonce" || -z "$gui_pid" ]]; then
    echo "[TraceOS] Control Centre session identity was not on the serial log." >&2
    exit 1
fi

# A 500px jump is amplified by pointer acceleration and misses the window.
# From the top-left, 140,150 is the sidebar (measured on the last dashboard shot).
focus_control_centre_window() {
    local tag="$1"
    hmp_command "$monitor" "mouse_move -2048 -1536" "$STATE/monitor-$tag-reset.log"
    hmp_command "$monitor" "mouse_move 140 150" "$STATE/monitor-$tag-target.log"
    hmp_command "$monitor" "mouse_button 1" "$STATE/monitor-$tag-down.log"
    sleep 0.2
    hmp_command "$monitor" "mouse_button 0" "$STATE/monitor-$tag-up.log"
    sleep 0.6
}
focus_control_centre_window "before-pages"

# Ctrl+H is backspace and never reached Tk. Overview is Ctrl+Shift+P.
# Ctrl+M is Return, so Network is Ctrl+Shift+B.
capture_workspace_page overview p OVERVIEW_PAGE_RENDERED OVERVIEW yes
capture_workspace_page cases k CASES_PAGE_RENDERED CASES
capture_workspace_page evidence e EVIDENCE_PAGE_RENDERED EVIDENCE
capture_workspace_page investigation o osint-page-rendered INVESTIGATION
capture_workspace_page network b NETWORK_PAGE_RENDERED NETWORK
capture_workspace_page tools t TOOLS_PAGE_RENDERED TOOLS
capture_workspace_page ai y AI_PAGE_RENDERED AI
capture_workspace_page settings g SETTINGS_PAGE_RENDERED SETTINGS
capture_workspace_page web-testing w WEB_TESTING_PAGE_RENDERED WEB_TESTING
capture_workspace_page image-osint i image-osint-page-rendered IMAGE_OSINT
cat "$workspace_matrix"

# The Applications menu is captured after the New Case and Image OSINT chords.
# Opening it here stole keyboard focus, and the later click did not give it back,
# so Ctrl+Shift+N never reached Control Centre.

# Diagnostic-only New Case GUI interaction. This uses the normal visible Control Centre
# shortcut/button path and never calls CaseStore.create() outside the GUI process.
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
        # Bound each search to the recent serial tail so a noisy boot log
        # cannot turn a bounded marker wait into an unbounded scan.
        if tail -n 5000 "$serial_log" 2>/dev/null | grep -Fq -- "$needle"; then
            return 0
        fi
        sleep 1
    done
    return 1
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
if wait_for_serial "QEMU_UI_DIAG_READY" 45; then
    collector_ready="yes"
fi
if [[ "$collector_ready" != "yes" ]]; then
    echo "[TraceOS] QEMU diagnostic collector did not become ready; wallpaper/theme verification cannot be claimed." >&2
    exit 1
fi

if ! wait_for_serial "stage=TRACEOS_DESKTOP_BRANDING_RESULT result=PASS" 45; then
    echo "[TraceOS] Verified desktop branding result was not observed." >&2
    tail -n 220 "$serial_log" >&2 || true
    exit 1
fi
branding_summary="$(grep -F 'stage=TRACEOS_DESKTOP_BRANDING_RESULT result=PASS' "$serial_log" | tail -n 1)"
if [[ "$branding_summary" != *"xsettings_theme=TraceOS"* || "$branding_summary" != *"png_width=1920"* || "$branding_summary" != *"png_height=1080"* ]]; then
    echo "[TraceOS] Runtime branding summary lacks the expected GTK theme or packaged PNG dimensions." >&2
    echo "$branding_summary" >&2
    exit 1
fi
runtime_wallpaper_sha256="$(extract_field "$branding_summary" png_sha256)"
if [[ ! "$runtime_wallpaper_sha256" =~ ^[0-9a-f]{64}$ || "$runtime_wallpaper_sha256" != "$packaged_wallpaper_sha256" ]]; then
    echo "[TraceOS] Guest wallpaper checksum does not match the packaged ISO asset." >&2
    echo "runtime=$runtime_wallpaper_sha256 packaged=$packaged_wallpaper_sha256" >&2
    exit 1
fi
required_targets="$(extract_field "$branding_summary" targets)"
target_passes="$(grep -Fc 'stage=TRACEOS_DESKTOP_BRANDING_TARGET result=PASS' "$serial_log" || true)"
if [[ ! "$required_targets" =~ ^[0-9]+$ || ! "$target_passes" =~ ^[0-9]+$ ]] || (( target_passes < required_targets )); then
    echo "[TraceOS] Runtime wallpaper targets are not all individually verified." >&2
    echo "$branding_summary" >&2
    exit 1
fi
if grep -Fq 'stage=TRACEOS_GTK_THEME_ERROR' "$serial_log"; then
    echo "[TraceOS] GTK theme/CSS errors were captured in the guest session." >&2
    grep -F 'stage=TRACEOS_GTK_THEME_ERROR' "$serial_log" >&2 || true
    exit 1
fi
printf 'TRACEOS_RUNTIME_BRANDING_RESULT=PASS\nTRACEOS_RUNTIME_WALLPAPER_SHA256=%s\n' "$runtime_wallpaper_sha256" >>"$OUT/traceos-wallpaper-manifest.txt"

hmp_new_case="yes"
if ! hmp_command "$monitor" "sendkey ctrl-shift-n" "$STATE/monitor-new-case-sendkey.log"; then
    hmp_new_case="no"
fi

attempt=""
if [[ -n "$gui_nonce" && -n "$gui_pid" ]]; then
    # The GUI event logger writes to serial asynchronously after HMP accepts
    # the key. Wait for the nonce/PID-scoped input marker before capturing its
    # attempt number, otherwise a fast grep can race the event and default to
    # attempt=1 while the actual dialog is attempt=2 (or later).
    for _ in $(seq 1 15); do
        input_line="$(grep -F "stage=NEW_CASE_INPUT_RECEIVED" "$serial_log" 2>/dev/null \
            | grep -F "nonce=$gui_nonce" \
            | grep -F "pid=$gui_pid" \
            | tail -n 1 || true)"
        if [[ -n "$input_line" ]]; then
            attempt="$(extract_field "$input_line" attempt)"
            break
        fi
        sleep 1
    done
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

# Diagnostic-only Image OSINT interaction against an opt-in synthetic fixture.
image_matrix="$OUT/traceos-image-osint-matrix.txt"
image_page_ppm="$OUT/traceos-image-page.ppm"
image_page_png="$OUT/traceos-image-page.png"
image_selected_ppm="$OUT/traceos-image-selected.ppm"
image_selected_png="$OUT/traceos-image-selected.png"
image_result_ppm="$OUT/traceos-image-result.ppm"
image_result_png="$OUT/traceos-image-result.png"
image_fixture="/home/traceos/traceosimage.png"
image_expected_sha="431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
image_ready="no"
image_page="no"
image_selected="no"
image_start="no"
image_selected_attempt="unknown"
image_start_attempt="unknown"
image_result_attempt="unknown"
image_cli_started="no"
image_cli_completed="no"
image_result_rendered="no"
image_failed="no"

image_marker_line() {
    local stage="$1"
    local attempt="${2:-}"
    local result
    result="$(tail -n +"${image_serial_mark:-1}" "$serial_log" 2>/dev/null \
        | grep -F "stage=$stage" \
        | grep -F "nonce=$gui_nonce" \
        | grep -F "pid=$gui_pid" \
        | tail -n 1 || true)"
    if [[ -n "$attempt" && -n "$result" ]]; then
        echo "$result" | grep -F "image_attempt=$attempt" | tail -n 1 || true
    else
        echo "$result"
    fi
}

wait_for_serial "TRACEOS_IMAGE_E2E_FIXTURE_READY=1" 90 && image_ready="yes" || true

if [[ "$image_ready" == "yes" ]]; then
    fixture_line="$(grep -F "TRACEOS_IMAGE_E2E_FIXTURE_READY=1" "$serial_log" | tail -n 1 || true)"
    fixture_sha="$(echo "$fixture_line" | sed -n 's/.*sha256=\([^ ]*\).*/\1/p')"
    fixture_size="$(echo "$fixture_line" | sed -n 's/.*size=\([0-9]*\).*/\1/p')"
    if [[ "$fixture_sha" != "$image_expected_sha" || "$fixture_size" != "68" ]]; then
        echo "[TraceOS] Synthetic image fixture mismatch." >&2
        image_ready="no"
    fi
fi

if [[ "$image_ready" == "yes" ]]; then
    image_serial_mark="$(( $(wc -l < "$serial_log" | tr -d ' ') + 1 ))"
    hmp_command "$monitor" "sendkey ctrl-shift-i" "$STATE/monitor-image-page-shortcut.log"
    for _ in $(seq 1 30); do
        if [[ -n "$(image_marker_line "image-osint-page-rendered")" ]]; then
            image_page="yes"
            break
        fi
        sleep 1
    done

    if [[ "$image_page" == "yes" ]]; then
        capture_screendump "$monitor" "$image_page_ppm" "$STATE/monitor-image-page-screendump.log"
        convert "$image_page_ppm" -resize 1280x720 -strip "$image_page_png"
        identify "$image_page_png"
        if [[ -s "$new_case_final_png" ]] && cmp -s "$image_page_png" "$new_case_final_png"; then
            echo "[TraceOS] Image page screenshot is a stale copy of the New Case result." >&2
            image_page="no"
            image_failed="yes"
        fi

        send_image_path() {
            local i ch key log
            for ((i=0; i<${#image_fixture}; i++)); do
                ch="${image_fixture:i:1}"
                case "$ch" in
                    /) key="slash" ;;
                    .) key="dot" ;;
                    *) key="$ch" ;;
                esac
                log="$STATE/monitor-image-key-$i.log"
                hmp_command "$monitor" "sendkey $key" "$log"
            done
        }

        send_image_path
        hmp_command "$monitor" "sendkey ret" "$STATE/monitor-image-use-path.log" || true

        for _ in $(seq 1 20); do
            source_line="$(image_marker_line "IMAGE_SOURCE_SELECTED")"
            if [[ -n "$source_line" ]]; then
                image_selected="yes"
                image_selected_attempt="$(echo "$source_line" | sed -n 's/.*image_attempt=\([^ ]*\).*/\1/p')"
                break
            fi
            sleep 1
        done

        if [[ "$image_selected" == "yes" ]]; then
            capture_screendump "$monitor" "$image_selected_ppm" "$STATE/monitor-image-selected-screendump.log"
            convert "$image_selected_ppm" -resize 1280x720 -strip "$image_selected_png"
            identify "$image_selected_png"
            hmp_command "$monitor" "sendkey ret" "$STATE/monitor-image-start.log" || true

            for _ in $(seq 1 30); do
                start_line="$(image_marker_line "IMAGE_ANALYSIS_START_CLICKED")"
                if [[ -n "$start_line" ]]; then
                    image_start="yes"
                    image_start_attempt="$(echo "$start_line" | sed -n 's/.*image_attempt=\([^ ]*\).*/\1/p')"
                    break
                fi
                sleep 1
            done
        fi

        for _ in $(seq 1 60); do
            if [[ "$image_selected_attempt" != "unknown" ]]; then
                [[ -n "$(image_marker_line "IMAGE_CLI_STARTED" "$image_selected_attempt")" ]] && image_cli_started="yes"
                [[ -n "$(image_marker_line "IMAGE_CLI_COMPLETED" "$image_selected_attempt")" ]] && image_cli_completed="yes"
                [[ -n "$(image_marker_line "IMAGE_RESULT_RENDERED" "$image_selected_attempt")" ]] && image_result_rendered="yes"
                [[ -n "$(image_marker_line "IMAGE_CLI_STOPPED" "$image_selected_attempt")" ]] && image_failed="yes"
            fi
            [[ "$image_result_rendered" == "yes" || "$image_failed" == "yes" ]] && break
            sleep 1
        done

        if [[ "$image_result_rendered" == "yes" ]]; then
            result_line="$(image_marker_line "IMAGE_RESULT_RENDERED" "$image_selected_attempt")"
            result_attempt="$(echo "$result_line" | sed -n 's/.*image_attempt=\([^ ]*\).*/\1/p')"
            image_result_attempt="${result_attempt:-unknown}"
            result_status="$(echo "$result_line" | sed -n 's/.*status=\([^ ]*\).*/\1/p')"
            result_sha="$(echo "$result_line" | sed -n 's/.*sha256=\([^ ]*\).*/\1/p')"
            result_unchanged="$(echo "$result_line" | sed -n 's/.*source_unchanged=\([^ ]*\).*/\1/p')"
            result_mime="$(echo "$result_line" | sed -n 's/.*mime=\([^ ]*\).*/\1/p')"
            if [[ "$result_attempt" != "$image_selected_attempt" || "$result_status" != "ok" || "$result_sha" != "$image_expected_sha" || "$result_unchanged" != "True" || "$result_mime" != "image/png" ]]; then
                image_result_rendered="no"
                image_failed="yes"
            else
                capture_screendump "$monitor" "$image_result_ppm" "$STATE/monitor-image-result-screendump.log"
                convert "$image_result_ppm" -resize 1280x720 -strip "$image_result_png"
                identify "$image_result_png"
            fi
        fi
    fi
fi

{
    echo "STATUS=$([[ "$image_result_rendered" == "yes" ]] && echo PASS || echo UNKNOWN)"
    echo "FIXTURE_READY=$image_ready"
    echo "PAGE_RENDERED=$image_page"
    echo "SOURCE_SELECTED=$image_selected"
    echo "START_CALLBACK=$image_start"
    echo "SOURCE_ATTEMPT=$image_selected_attempt"
    echo "START_ATTEMPT=$image_start_attempt"
    attempt_match="no"
    if [[ "$image_selected_attempt" != "unknown" && "$image_start_attempt" != "unknown" && "$image_selected_attempt" == "$image_start_attempt" ]]; then
        attempt_match="yes"
    fi
    echo "ATTEMPT_MATCH=$attempt_match"
    echo "RESULT_ATTEMPT=$image_result_attempt"
    echo "CLI_STARTED=$image_cli_started"
    echo "CLI_COMPLETED=$image_cli_completed"
    echo "RESULT_RENDERED=$image_result_rendered"
    echo "EXPECTED_FIXTURE_SHA=$image_expected_sha"
} >"$image_matrix"

dashboard_png="$OUT/traceos-dashboard.png"
dashboard_hash="$(sha256sum "$dashboard_png" | awk '{print $1}')"
dialog_hash="$(sha256sum "$new_case_dialog_png" 2>/dev/null | awk '{print $1}' || true)"
filled_hash="$(sha256sum "${OUT}/traceos-new-case-filled.png" 2>/dev/null | awk '{print $1}' || true)"
final_hash="$(sha256sum "$new_case_final_png" | awk '{print $1}')"
pixel_diff_dashboard_final="$(compare -metric AE "$dashboard_png" "$new_case_final_png" null: 2>&1 || true)"
pixel_diff_dialog_filled="$(compare -metric AE "$new_case_dialog_png" "${OUT}/traceos-new-case-filled.png" null: 2>&1 || true)"
pixel_diff_filled_final="$(compare -metric AE "${OUT}/traceos-new-case-filled.png" "$new_case_final_png" null: 2>&1 || true)"

if [[ -n "$case_id" ]]; then
    header_marker="$(marker_line "NEW_CASE_HEADER_REFRESHED")"
    header_case_id="$(extract_field "$header_marker" case_id)"
    header_prefix="$(extract_field "$header_marker" id_prefix)"
    if [[ "$header_case_id" == "$case_id" && ${#header_prefix} -eq 8 && "$header_prefix" == "${case_id:0:8}" ]]; then
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
    echo "GUI_NONCE=${gui_nonce:-unknown}"
    echo "GUI_PID=${gui_pid:-unknown}"
    echo "GUI_UID=${gui_uid:-unknown}"
    echo "ATTEMPT=$attempt"
    echo "NEW_CASE_INPUT_RECEIVED=$input_received"
    echo "NEW_CASE_DIALOG_OPENED=$dialog_opened"
    echo "NEW_CASE_CREATE_CALLBACK_ENTERED=$callback_entered"
    echo "NEW_CASE_CREATED=$case_created"
    echo "CASE_ID=${case_id:-unknown}"
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

# These matrices are release-gating tests, not optional diagnostics. Preserve
# screenshots and logs on failure so the next investigation has real evidence.
if ! assert_ui_matrix_status "$status" "$image_result_rendered"; then
    echo "[TraceOS] New Case matrix:" >&2
    cat "$new_case_matrix" >&2 || true
    echo "[TraceOS] Image OSINT matrix:" >&2
    cat "$image_matrix" >&2 || true
    exit 1
fi
echo "[TraceOS] Required QEMU GUI interaction matrices: PASS"

# Capture the Applications menu only after the keyboard chords. The menu click
# takes focus away from Control Centre.
launcher_menu_ppm="$OUT/traceos-launcher-menu.ppm"
launcher_menu_png="$OUT/traceos-launcher-menu.png"
hmp_command "$STATE/monitor-dashboard.sock" "mouse_move -2048 -1536" "$STATE/monitor-launcher-menu-reset-pointer.log"
hmp_command "$STATE/monitor-dashboard.sock" "mouse_move 45 10" "$STATE/monitor-launcher-menu-target-button.log"
hmp_command "$STATE/monitor-dashboard.sock" "mouse_button 1" "$STATE/monitor-launcher-menu-mouse-down.log"
sleep 0.2
hmp_command "$STATE/monitor-dashboard.sock" "mouse_button 0" "$STATE/monitor-launcher-menu-mouse-up.log"
sleep 2
capture_screendump "$STATE/monitor-dashboard.sock" "$launcher_menu_ppm" "$STATE/monitor-launcher-menu-screendump.log"
convert "$launcher_menu_ppm" -resize 1280x720 -strip "$launcher_menu_png"
identify "$launcher_menu_png"
test -s "$launcher_menu_png"
launcher_dashboard_crop="$OUT/.traceos-dashboard-launcher-region.png"
launcher_menu_crop="$OUT/.traceos-launcher-menu-region.png"
convert "$OUT/traceos-dashboard.png" -crop 300x500+0+24 +repage "$launcher_dashboard_crop"
convert "$launcher_menu_png" -crop 300x500+0+24 +repage "$launcher_menu_crop"
launcher_menu_diff="$(compare -metric AE "$launcher_dashboard_crop" "$launcher_menu_crop" null: 2>&1 || true)"
if ! popup_region_diff_passes "$launcher_menu_diff"; then
    echo "[TraceOS] Applications menu was not visibly open in the expected popup region (changed pixels: ${launcher_menu_diff:-unknown})." >&2
    exit 1
fi
echo "[TraceOS] Applications menu visible in popup region; $launcher_menu_diff pixels changed."
hmp_command "$STATE/monitor-dashboard.sock" "sendkey esc" "$STATE/monitor-launcher-menu-dismiss.log"
sleep 0.5
rm -f "$launcher_menu_ppm" "$launcher_dashboard_crop" "$launcher_menu_crop"

rm -f "$OUT"/*.ppm

# Capture the desktop underneath the Launcher/Control Centre after all other GUI
# checks. Keep QEMU alive until this final screenshot has been captured because
# the capture uses the still-open HMP monitor socket. The same large negative
# relative delta makes pointer placement repeatable.
hmp_command "$STATE/monitor-dashboard.sock" "mouse_move -2048 -1536" "$STATE/monitor-desktop-home-pointer-reset.log"
hmp_command "$STATE/monitor-dashboard.sock" "mouse_move 1100 690" "$STATE/monitor-desktop-home-pointer-park.log"
hmp_command "$STATE/monitor-dashboard.sock" "sendkey alt-f9" "$STATE/monitor-desktop-home-minimize.log"
sleep 2
desktop_home_ppm="$OUT/traceos-desktop-home.ppm"
desktop_home_png="$OUT/traceos-desktop-home.png"
capture_screendump "$STATE/monitor-dashboard.sock" "$desktop_home_ppm" "$STATE/monitor-desktop-home-screendump.log"
convert "$desktop_home_ppm" -resize 1280x720 -strip "$desktop_home_png"
identify "$desktop_home_png"
test -s "$desktop_home_png"
# Compare the uncovered desktop with a screenshot known to contain the Control Centre.
# traceos-dashboard.png is captured immediately after the launcher transition and can
# still show the desktop while the Control Centre window is behind it, so it is not a
# trustworthy visible-window baseline for this assertion.
desktop_home_diff="$(compare -metric AE "$new_case_final_png" "$desktop_home_png" null: 2>&1 || true)"
desktop_home_spread="$(convert "$desktop_home_png" -resize 160x90 -colorspace Gray -format "%[fx:standard_deviation]" info:)"
if [[ ! "$desktop_home_diff" =~ ^[0-9]+$ ]] || (( desktop_home_diff <= 100000 )); then
    echo "[TraceOS] Minimizing Control Centre did not reveal a distinct desktop home screen." >&2
    exit 1
fi
if ! awk "BEGIN { exit !($desktop_home_spread > 0.02) }"; then
    echo "[TraceOS] The uncovered desktop is blank or static." >&2
    exit 1
fi
echo "[TraceOS] Uncovered TraceOS desktop home screen captured; changed pixels: $desktop_home_diff."
rm -f "$desktop_home_ppm"

# Verify the pixels actually painted by XFCE, not just the xfconf property
# value. Exclude the top panel, left-side shortcuts and bottom dock from the crop.
wallpaper_visual_status="no"
desktop_width="$(identify -format '%w' "$desktop_home_png")"
desktop_height="$(identify -format '%h' "$desktop_home_png")"
wallpaper_crop_x=140
wallpaper_crop_y=35
wallpaper_crop_width=$((desktop_width - 280))
wallpaper_crop_height=$((desktop_height - 100))
if (( wallpaper_crop_width > 200 && wallpaper_crop_height > 200 )); then
    wallpaper_expected_fit="$OUT/traceos-wallpaper-expected-fit.png"
    wallpaper_actual_crop="$OUT/traceos-desktop-wallpaper-region.png"
    wallpaper_expected_crop="$OUT/traceos-wallpaper-expected-region.png"
    convert "$packaged_wallpaper_png" -resize "${desktop_width}x${desktop_height}^" \
        -gravity center -extent "${desktop_width}x${desktop_height}" "$wallpaper_expected_fit"
    convert "$desktop_home_png" -crop "${wallpaper_crop_width}x${wallpaper_crop_height}+${wallpaper_crop_x}+${wallpaper_crop_y}" \
        +repage "$wallpaper_actual_crop"
    convert "$wallpaper_expected_fit" -crop "${wallpaper_crop_width}x${wallpaper_crop_height}+${wallpaper_crop_x}+${wallpaper_crop_y}" \
        +repage "$wallpaper_expected_crop"
    wallpaper_mae="$(compare -metric MAE "$wallpaper_actual_crop" "$wallpaper_expected_crop" null: 2>&1 || true)"
    # ImageMagick prints raw MAE followed by a normalized MAE in parentheses,
    # e.g. "60.5701 (0.000924241)". The normalized value is the one compared
    # with a 0..1 threshold; comparing the raw first number rejects correct art.
    wallpaper_mae_raw="${wallpaper_mae%% *}"
    wallpaper_mae_normalized="$(printf '%s\n' "$wallpaper_mae" | sed -n 's/.*(\([0-9][0-9.]*\)).*/\1/p')"
    actual_wallpaper_mean="$(convert "$wallpaper_actual_crop" -format '%[fx:mean]' info:)"
    echo "[TraceOS] Rendered wallpaper crop MAE: raw=${wallpaper_mae_raw:-unknown} normalized=${wallpaper_mae_normalized:-unknown} desktop_mean=${actual_wallpaper_mean:-unknown} (normalized threshold below 0.08, mean above 0.10)."
    if [[ "$wallpaper_mae_normalized" =~ ^[0-9]+([.][0-9]+)?$ ]] && \
        awk "BEGIN { exit !($wallpaper_mae_normalized < 0.08) }" && \
        awk "BEGIN { exit !($actual_wallpaper_mean > 0.10) }"; then
        wallpaper_visual_status="yes"
        echo "[TraceOS] Packaged TraceOS wallpaper is visibly rendered in the uncovered desktop."
    else
        echo "[TraceOS] FAIL: Xfconf readback passed, but the uncovered desktop pixels do not match the packaged TraceOS wallpaper." >&2
    fi
else
    echo "[TraceOS] FAIL: desktop screenshot is too small for the wallpaper verification crop." >&2
fi

# Launch a known native GTK 3 dialog through XFCE Application Finder.
# Wait for the finder to actually appear before typing. Under QEMU TCG,
# the Alt+F2 shortcut can take several seconds; the old fixed 1s sleep
# let all keypresses hit the desktop before the finder existed.
native_gtk_ppm="$OUT/traceos-native-gtk.ppm"
native_gtk_png="$OUT/traceos-native-gtk.png"
native_menu_ppm="$OUT/traceos-native-gtk-menu.ppm"
native_menu_png="$OUT/traceos-native-gtk-menu.png"
native_gtk_baseline_crop="$OUT/.traceos-native-gtk-baseline-center.png"
native_gtk_desktop_crop="$OUT/.traceos-native-gtk-desktop-center.png"
native_gtk_candidate_crop="$OUT/.traceos-native-gtk-candidate-center.png"
native_gtk_status="no"
native_gtk_appfinder_visible="no"

hmp_command "$STATE/monitor-dashboard.sock" "mouse_move -2048 -1536" "$STATE/monitor-native-gtk-pointer-reset.log"
hmp_command "$STATE/monitor-dashboard.sock" "sendkey alt-f2" "$STATE/monitor-native-gtk-appfinder-open.log"

# All captures are normalized to the exact desktop-home dimensions before
# pixel comparison. Build #516 showed that stretching 1280x800 to 1280x720
# made the wallpaper itself differ and falsely satisfied the GTK assertion.
convert "$desktop_home_png" -crop "700x520+226+80" +repage "$native_gtk_baseline_crop"
for native_gtk_wait in $(seq 1 20); do
    capture_screendump "$STATE/monitor-dashboard.sock" "$native_menu_ppm" "$STATE/monitor-native-gtk-appfinder-wait-$native_gtk_wait.log"
    convert "$native_menu_ppm" -resize "$desktop_width"x"$desktop_height"! -strip "$native_menu_png"
    convert "$native_menu_png" -crop "700x520+226+80" +repage "$native_gtk_candidate_crop"
    native_gtk_appfinder_metric="$(compare -metric AE "$native_gtk_baseline_crop" "$native_gtk_candidate_crop" null: 2>&1 || true)"
    native_gtk_appfinder_diff="${native_gtk_appfinder_metric%% *}"
    echo "[TraceOS] Application Finder visibility probe attempt=$native_gtk_wait changed_pixels=${native_gtk_appfinder_diff:-unknown}."
    if [[ "$native_gtk_appfinder_diff" =~ ^[0-9]+$ ]] && (( native_gtk_appfinder_diff > 40000 )); then
        native_gtk_appfinder_visible="yes"
        break
    fi
    sleep 1
done
if [[ "$native_gtk_appfinder_visible" != "yes" ]]; then
    echo "[TraceOS] FAIL: XFCE Application Finder did not visibly appear after Alt+F2; refusing to type into an unverified focus target." >&2
    exit 1
fi
echo "[TraceOS] XFCE Application Finder visibly appeared; typing native GTK test command."

# Compare the final screen to the actual visible Application Finder, not to
# a bare wallpaper. This means the finder itself cannot satisfy the dialog
# assertion. Leave at least 150ms between guest key events so QEMU TCG does
# not overlap key-down intervals and drop characters.
# The old preferred-applications helper is not shipped in Debian 13.
# Collapsed Application Finder still accepts a missing command and Return,
# but xfce_spawn only sets the entry error icon, so the central window
# never changes. xfce4-mime-settings is the installed GTK 3 Default
# Applications dialog.
convert "$native_menu_png" -crop "700x520+226+80" +repage "$native_gtk_baseline_crop"
native_gtk_command="xfce4-mime-settings"
while IFS= read -r native_gtk_key; do
    [[ "$native_gtk_key" == "-" ]] && native_gtk_key="minus"
    hmp_command "$STATE/monitor-dashboard.sock" "sendkey $native_gtk_key" "$STATE/monitor-native-gtk-command-key-$native_gtk_key.log"
    sleep 0.15
done < <(printf "%s" "$native_gtk_command" | fold -w1)
hmp_command "$STATE/monitor-dashboard.sock" "sendkey ret" "$STATE/monitor-native-gtk-command-launch.log"

# Poll for a real dialog. A still-visible Application Finder must fail, and so
# must a finder that merely closes back to the desktop: that dismissal is
# ~66k central pixels and would otherwise satisfy the finder-only threshold.
convert "$desktop_home_png" -crop "700x520+226+80" +repage "$native_gtk_desktop_crop"
for native_gtk_wait in $(seq 1 20); do
    capture_screendump "$STATE/monitor-dashboard.sock" "$native_gtk_ppm" "$STATE/monitor-native-gtk-verify-$native_gtk_wait.log"
    convert "$native_gtk_ppm" -resize "$desktop_width"x"$desktop_height"! -strip "$native_gtk_png"
    convert "$native_gtk_png" -crop "700x520+226+80" +repage "$native_gtk_candidate_crop"
    native_gtk_metric="$(compare -metric AE "$native_gtk_baseline_crop" "$native_gtk_candidate_crop" null: 2>&1 || true)"
    native_gtk_diff="${native_gtk_metric%% *}"
    native_gtk_desktop_metric="$(compare -metric AE "$native_gtk_desktop_crop" "$native_gtk_candidate_crop" null: 2>&1 || true)"
    native_gtk_desktop_diff="${native_gtk_desktop_metric%% *}"
    echo "[TraceOS] Native GTK replacement probe attempt=$native_gtk_wait finder_changed=${native_gtk_diff:-unknown} desktop_changed=${native_gtk_desktop_diff:-unknown} (both required >40000)."
    if [[ "$native_gtk_diff" =~ ^[0-9]+$ && "$native_gtk_desktop_diff" =~ ^[0-9]+$ ]] && (( native_gtk_diff > 40000 && native_gtk_desktop_diff > 40000 )); then
        native_gtk_status="yes"
        break
    fi
    sleep 1
done
if [[ "$native_gtk_status" == "yes" ]]; then
    echo "[TraceOS] Native GTK 3 Default Applications dialog visibly replaced Application Finder; changed pixels: $native_gtk_diff."
else
    echo "[TraceOS] FAIL: native GTK 3 Default Applications dialog did not visibly replace Application Finder in the central screen region." >&2
fi
hmp_command "$STATE/monitor-dashboard.sock" "sendkey esc" "$STATE/monitor-native-gtk-close.log"

python3 - "$STATE/serial-dashboard.log" "$OUT/traceos-desktop-setup.log" "$OUT/traceos-xrandr-runtime.txt" "$OUT/traceos-xfconf-desktop-initial.txt" "$OUT/traceos-xfconf-desktop-runtime.txt" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import unquote

serial_path, setup_path, xrandr_path, xfconf_initial_path, xfconf_path = map(Path, sys.argv[1:])
setup_lines = []
xrandr_lines = []
xfconf_initial_lines = []
xfconf_final_lines = []
for line in serial_path.read_text(encoding="utf-8", errors="replace").splitlines():
    marker = "stage=TRACEOS_DESKTOP_SETUP_LOG_LINE text="
    if marker in line:
        setup_lines.append(unquote(line.split(marker, 1)[1]))
    marker = "stage=TRACEOS_DESKTOP_RUNTIME_PROPERTY "
    if marker not in line:
        continue
    record = line.split(marker, 1)[1]
    fields = dict(re.findall(r"([a-z_]+)=([^ ]+)", record))
    kind = fields.get("kind", "")
    if kind in {"xrandr_monitor", "xrandr_query"}:
        xrandr_lines.append(f"{kind}: {unquote(fields.get('line', ''))}")
    elif kind in {"xfconf_property", "xfconf_property_final"}:
        path = unquote(fields.get("path", ""))
        value = unquote(fields.get("value", ""))
        destination = xfconf_final_lines if kind == "xfconf_property_final" else xfconf_initial_lines
        destination.append(f"{path} {value}".rstrip())
if not setup_lines or not xrandr_lines or not xfconf_initial_lines or not xfconf_final_lines:
    print("[TraceOS] FAIL: required desktop setup, connected-output, or before/after xfconf evidence is missing.", file=sys.stderr)
    raise SystemExit(1)
setup_path.write_text("\n".join(setup_lines) + "\n", encoding="utf-8")
xrandr_path.write_text("\n".join(xrandr_lines) + "\n", encoding="utf-8")
xfconf_initial_path.write_text("\n".join(xfconf_initial_lines) + "\n", encoding="utf-8")
xfconf_path.write_text("\n".join(xfconf_final_lines) + "\n", encoding="utf-8")
print(f"[TraceOS] Retained runtime diagnostics: desktop_setup_lines={len(setup_lines)} xrandr_lines={len(xrandr_lines)} xfconf_initial_properties={len(xfconf_initial_lines)} xfconf_final_properties={len(xfconf_final_lines)}")
PY
rm -f "$native_gtk_ppm" "$native_menu_ppm" "$native_gtk_baseline_crop" "$native_gtk_desktop_crop" "$native_gtk_candidate_crop"
if [[ "$wallpaper_visual_status" != "yes" || "$native_gtk_status" != "yes" ]]; then
    echo "[TraceOS] GUI branding evidence gate failed: wallpaper=$wallpaper_visual_status native_gtk=$native_gtk_status." >&2
    exit 1
fi

kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID

echo "[TraceOS] QEMU screenshots and diagnostics ready:"
find "$OUT" -maxdepth 1 -type f \( -name '*.png' -o -name '*.cfg' -o -name '*.log' -o -name '*.txt' \) -print -exec ls -lh {} +
