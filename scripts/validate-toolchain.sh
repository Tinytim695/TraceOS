#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:?usage: validate-toolchain.sh ROOTFS}"
export LC_ALL=C

check_cmd() {
  local cmd="$1"
  local candidate target

  for candidate in "$ROOT/usr/bin/$cmd" "$ROOT/usr/local/bin/$cmd"; do
    if test -x "$candidate"; then
      printf '[OK] %s\n' "$cmd"
      return 0
    fi

    # Staged rootfs validation must resolve absolute symlinks inside ROOT,
    # not against the GitHub runner's live filesystem.
    if test -L "$candidate"; then
      target="$(readlink "$candidate")"
      case "$target" in
        /*) target="$ROOT$target" ;;
        *) target="$(dirname "$candidate")/$target" ;;
      esac
      if test -x "$target"; then
        printf '[OK] %s\n' "$cmd"
        return 0
      fi
    fi
  done

  printf '[MISSING] %s\n' "$cmd" >&2
  return 1
}

echo "[TraceOS] OSINT"
for cmd in sherlock maigret h8mail holehe blackbird phoneinfoga whois dig; do
  check_cmd "$cmd"
done

echo "[TraceOS] RED"
for cmd in nmap ffuf gobuster sqlmap whatweb wafw00f; do
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
