#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:?usage: validate-toolchain.sh ROOTFS}"
export LC_ALL=C
resolve_cmd() {
  local cmd="$1" candidate target current root_canon normalized
  root_canon="$(cd "$ROOT" && pwd -P)"

  for candidate in \
      "$root_canon/usr/bin/$cmd" \
      "$root_canon/usr/sbin/$cmd" \
      "$root_canon/usr/local/bin/$cmd"
  do
    current="$candidate"
    declare -A seen=()
    for depth in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
      normalized="$(realpath -m -- "$current")" || break
      case "$normalized" in
        "$root_canon/"*) ;;
        *) break ;;
      esac
      if [[ -n "\${seen["$normalized"]+seen}" ]]; then
        break
      fi
      seen["$normalized"]=1
      current="$normalized"

      # Resolve symlinks before checking executability. Absolute targets are
      # guest-rooted and never resolved against the CI host filesystem.
      if [[ -L "$current" ]]; then
        target="$(readlink "$current")" || break
        if [[ "$target" = /* ]]; then
          current="$root_canon$target"
        else
          current="$(dirname "$current")/$target"
        fi
        continue
      fi

      if [[ -f "$current" && -x "$current" ]]; then
        printf '%s\n' "$current"
        return 0
      fi
      break
    done
  done

  printf '[MISSING] %s\n' "$cmd" >&2
  return 1
}
check_cmd() { local cmd="$1"; resolve_cmd "$cmd" >/dev/null; printf '[OK] %s\n' "$cmd"; }

if [[ -n "\${TRACEOS_VALIDATE_CMD:-}" ]]; then
  check_cmd "$TRACEOS_VALIDATE_CMD"
  exit 0
fi
echo "[TraceOS] OSINT"
for cmd in sherlock maigret h8mail holehe blackbird phoneinfoga ghunt theHarvester dnsrecon dnstwist subfinder whois dig; do check_cmd "$cmd"; done
echo "[TraceOS] INFRASTRUCTURE RECON"
for cmd in dnsx httpx naabu; do check_cmd "$cmd"; done
echo "[TraceOS] WEB APPLICATION ASSESSMENT"
for cmd in nmap ffuf gobuster sqlmap whatweb wafw00f nuclei zap nikto dalfox; do check_cmd "$cmd"; done
echo "[TraceOS] BLOCK 6A OFFENSIVE OPERATIONS"
for cmd in msfconsole msfvenom msfdb enum4linux-ng; do check_cmd "$cmd"; done
echo "[TraceOS] BLOCK 6B AD / AUTHENTICATION ASSESSMENT"
for cmd in bloodhound-python kerbrute hashcat john; do check_cmd "$cmd"; done
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
