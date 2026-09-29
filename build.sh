#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Keep the bundled Blackbird lock in one authoritative source file.
install -D config/third-party/blackbird-requirements.txt   config/includes.chroot/usr/share/traceos/blackbird-requirements.txt

command -v lb >/dev/null 2>&1 || {
  echo "live-build is required. Install it with: sudo apt install live-build"
  exit 1
}

echo "[TraceOS] Cleaning previous build state..."
sudo lb clean --purge || true

echo "[TraceOS] Configuring Debian live image..."
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

echo "[TraceOS] Preparing executable build hooks..."
sudo chmod +x config/hooks/live/*.hook.chroot 2>/dev/null || true

echo "[TraceOS] Building ISO..."
sudo lb build

echo "[TraceOS] Build complete."
ls -lh live-image-amd64.hybrid.iso
