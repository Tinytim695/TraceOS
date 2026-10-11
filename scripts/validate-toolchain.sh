#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:?usage: validate-toolchain.sh ROOTFS}"
export LC_ALL=C

resolve_cmd() {
  local cmd="$1" resolved root_canon
  root_canon="$(cd -- "$ROOT" && pwd -P)"

  # Resolve path components one at a time. readlink -f alone can collapse
  # symlinks in parent directories and bypass the explicit chain-depth limit.
  if resolved="$(python3 - "$root_canon" "$cmd" <<'PY'
import os
import stat
import sys

root, command = sys.argv[1:]
if not command or command in (".", "..") or "/" in command:
    raise SystemExit(1)


def resolve_candidate(candidate, max_symlinks=16):
    relative = os.path.relpath(candidate, root)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return None

    pending = relative.split(os.sep)
    resolved = []
    seen = set()
    symlink_count = 0

    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                return None
            resolved.pop()
            continue

        probe = os.path.join(root, *resolved, component)
        try:
            metadata = os.lstat(probe)
        except OSError:
            return None

        if stat.S_ISLNK(metadata.st_mode):
            link_path = tuple(resolved + [component])
            if link_path in seen:
                return None
            seen.add(link_path)
            symlink_count += 1
            if symlink_count > max_symlinks:
                return None

            try:
                target = os.readlink(probe)
            except OSError:
                return None
            if os.path.isabs(target):
                resolved = []  # Absolute links are guest-root-relative.
            pending = target.lstrip("/").split("/") + pending
            continue

        if pending and not stat.S_ISDIR(metadata.st_mode):
            return None
        resolved.append(component)

    final_path = os.path.join(root, *resolved)
    try:
        final_info = os.lstat(final_path)
    except OSError:
        return None
    if not stat.S_ISREG(final_info.st_mode) or not os.access(final_path, os.X_OK):
        return None
    return final_path


for directory in ("usr/bin", "usr/sbin", "usr/local/bin"):
    found = resolve_candidate(os.path.join(root, directory, command))
    if found is not None:
        print(found)
        raise SystemExit(0)
raise SystemExit(1)
PY
)"; then
    printf '%s\n' "$resolved"
    return 0
  fi

  printf '[MISSING] %s\n' "$cmd" >&2
  return 1
}
check_cmd() { local cmd="$1"; resolve_cmd "$cmd" >/dev/null; printf '[OK] %s\n' "$cmd"; }

if [[ -n "${TRACEOS_VALIDATE_CMD:-}" ]]; then
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
