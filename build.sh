#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

configure_live_build() {
  sudo lb config \
    --mode debian \
    --distribution trixie \
    --architectures amd64 \
    --archive-areas "main contrib non-free non-free-firmware" \
    --mirror-bootstrap https://deb.debian.org/debian \
    --mirror-chroot https://deb.debian.org/debian \
    --mirror-binary https://deb.debian.org/debian \
    --mirror-debian-installer https://deb.debian.org/debian \
    --mirror-chroot-security https://security.debian.org/debian-security \
    --mirror-binary-security https://security.debian.org/debian-security \
    --security true \
    --binary-images iso-hybrid \
    --debian-installer live \
    --apt-recommends true \
    --linux-flavours amd64 \
    --bootappend-live "boot=live components username=traceos hostname=traceos console=ttyS0,115200n8"
}

# Production commands. A test may override these after sourcing with
# TRACEOS_BUILD_UNDER_TEST=1. The purge command must not hide failure.
lb_clean_purge() {
  sudo lb clean --purge
}

lb_build_once() {
  sudo lb build
}

lb_prepare_hooks() {
  sudo chmod +x config/hooks/live/*.hook.chroot 2>/dev/null || true
}

lb_retry_pause() {
  sleep 5
}

prepare_live_build() {
  echo "[TraceOS] Cleaning previous build state..."
  lb_clean_purge
  echo "[TraceOS] Configuring Debian live image..."
  configure_live_build
  echo "[TraceOS] Preparing executable build hooks..."
  lb_prepare_hooks
}

# Debian mirrors can occasionally reset a large package download on CI.
# Retries must not reuse stage markers from an incomplete build: a failed
# package fetch can leave live-build claiming the kernel stage is complete
# even though chroot/boot has no kernel image. A failed purge stops the
# retry instead of configuring over that partial state.
run_live_build_attempts() {
  local attempt
  for attempt in 1 2 3; do
    if lb_build_once; then
      return 0
    fi
    if [ "$attempt" -eq 3 ]; then
      echo "[TraceOS] live-build failed after 3 attempts." >&2
      return 1
    fi
    echo "[TraceOS] live-build attempt $attempt failed; purging partial state before retry." >&2
    lb_clean_purge
    configure_live_build
    lb_prepare_hooks
    lb_retry_pause
  done
}

if [[ "${TRACEOS_BUILD_UNDER_TEST:-0}" != "1" ]]; then
  cd "$ROOT"

  command -v lb >/dev/null 2>&1 || {
    echo "live-build is required. Install it with: sudo apt install live-build"
    exit 1
  }

  # Keep the bundled Blackbird lock in one authoritative source file.
  install -D config/third-party/blackbird-requirements.txt \
    config/includes.chroot/usr/share/traceos/blackbird-requirements.txt

  prepare_live_build

  echo "[TraceOS] Building ISO..."
  run_live_build_attempts

  echo "[TraceOS] Build complete."
  ls -lh live-image-amd64.hybrid.iso
fi
