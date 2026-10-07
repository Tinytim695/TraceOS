#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:?usage: validate-toolchain.sh ROOTFS}"
export LC_ALL=C
resolve_cmd() {
  local cmd="$1" candidate target current depth
  for candidate in "$ROOT/usr/bin/$cmd" "$ROOT/usr/local/bin/$cmd"; do
    current="$candidate"
    for depth in 1 2 3 4 5 6 7 8; do
      if test -x "$current"; then printf '%s\n' "$current"; return 0; fi
      if ! test -L "$current"; then break; fi
      target="$(readlink "$current")"
      case "$target" in
        /*) current="$ROOT$target" ;;
        *) current="$(dirname "$current")/$target" ;;
      esac
    done
  done
  printf '[MISSING] %s\n' "$cmd" >&2
  return 1
}
check_cmd() { local cmd="$1"; resolve_cmd "$cmd" >/dev/null; printf '[OK] %s\n' "$cmd"; }
echo "[TraceOS] OSINT"
for cmd in sherlock maigret h8mail holehe blackbird phoneinfoga subfinder whois dig; do check_cmd "$cmd"; done
echo "[TraceOS] INFRASTRUCTURE RECON"
for cmd in dnsx httpx naabu; do check_cmd "$cmd"; done
echo "[TraceOS] WEB APPLICATION ASSESSMENT"
for cmd in nmap ffuf gobuster sqlmap whatweb wafw00f nuclei zap nikto dalfox; do check_cmd "$cmd"; done
echo "[TraceOS] BLUE / DFIR"
for cmd in tcpdump tshark wireshark yara; do check_cmd "$cmd"; done
for cmd in fls mmls tsk_recover; do check_cmd "$cmd"; done
for cmd in plaso-log2timeline plaso-psort; do check_cmd "$cmd"; done
for cmd in suricata suricata-update; do check_cmd "$cmd"; done
for cmd in vol sigma; do check_cmd "$cmd"; done
echo "[TraceOS] ENTERPRISE / ACTIVE DIRECTORY"
for cmd in nxc certipy ldapsearch smbclient rpcclient kinit kvno; do check_cmd "$cmd"; done
for cmd in GetNPUsers.py GetUserSPNs.py GetADUsers.py; do check_cmd "$cmd"; done
echo "[TraceOS] PURPLE"
check_cmd traceos-purple
echo "[TraceOS] All required OSINT/Recon/Web/Red/Blue/DFIR/Enterprise/Purple command surfaces are packaged."
