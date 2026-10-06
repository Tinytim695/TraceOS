#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:?usage: validate-toolchain.sh ROOTFS}"
export LC_ALL=C

check_cmd() {
  local cmd="$1"
  if test -x "$ROOT/usr/bin/$cmd" || test -x "$ROOT/usr/local/bin/$cmd"; then
    printf '[OK] %s\n' "$cmd"
  else
    printf '[MISSING] %s\n' "$cmd" >&2
    return 1
  fi
}

echo "[TraceOS] OSINT"
for cmd in sherlock maigret h8mail blackbird whois dig; do
  check_cmd "$cmd"
done

echo "[TraceOS] RED"
for cmd in nmap ffuf gobuster sqlmap; do
  check_cmd "$cmd"
done

echo "[TraceOS] BLUE / DFIR"
for cmd in tcpdump tshark wireshark yara; do
  check_cmd "$cmd"
done
for cmd in fls mmls tsk_recover; do
  check_cmd "$cmd"
done
for cmd in plaso-log2timeline plaso-psort; do
  check_cmd "$cmd"
done

echo "[TraceOS] PURPLE"
check_cmd traceos-purple

echo "[TraceOS] All required OSINT/Red/Blue/Purple command surfaces are packaged."
