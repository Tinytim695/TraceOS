#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[TraceOS] Static preflight: syntax, shebangs and manifests"

while IFS= read -r -d '' file; do
    first="$(head -n 1 "$file" || true)"
    case "$first" in
        '#!'*python*)
            echo "[TraceOS] Python: $file"
            PYTHONPYCACHEPREFIX="\${TMPDIR:-/tmp}/traceos-pycache" \
                python3 -m py_compile "$file"
            ;;
        '#!'*'/bin/bash'*|'#!'*/env\ bash*)
            echo "[TraceOS] Bash: $file"
            bash -n "$file"
            shellcheck -S error --shell=bash "$file"
            ;;
        '#!'*'/bin/sh'*|'#!'*/env\ sh*)
            echo "[TraceOS] POSIX sh: $file"
            dash -n "$file"
            shellcheck -S error --shell=sh "$file"
            ;;
        '#!'*)
            echo "[TraceOS] Unclassified shebang in $file: $first"
            ;;
    esac
done < <(
    find \
        config/hooks/live \
        config/includes.chroot/usr/local/bin \
        config/includes.chroot/usr/local/sbin \
        scripts \
        -type f -print0
)

echo "[TraceOS] Manifest contract checks"
python3 - <<'PY'
from pathlib import Path

for path in (
    Path("config/includes.chroot/usr/share/traceos/projectdiscovery-tools.txt"),
    Path("config/includes.chroot/usr/share/traceos/web-assessment-tools.txt"),
):
    lines = path.read_text(encoding="utf-8").splitlines()
    headers = [line for line in lines if line.startswith("# project|")]
    assert len(headers) == 1, (path, headers)
    assert headers[0].count("|") == 7, (path, headers[0])
    assert headers[0].endswith("|release_url"), (path, headers[0])
    rows = [line for line in lines if line and not line.startswith("#")]
    assert rows, path
    for row in rows:
        fields = row.split("|")
        assert len(fields) == 8, (path, row)
        assert fields[7].startswith("https://"), (path, row)

recon = Path("config/hooks/live/0205-traceos-recon.hook.chroot").read_text(encoding="utf-8")
web = Path("config/hooks/live/0220-traceos-web-assessment.hook.chroot").read_text(encoding="utf-8")
assert "cat > /usr/share/traceos/projectdiscovery-tools.txt" not in recon
assert "cat > /usr/share/traceos/web-assessment-tools.txt" not in web
print("manifest_contracts=PASS")
PY

echo "[TraceOS] Targeted host fixtures"
python3 -m unittest discover -s tests -p 'test_validate_toolchain.py' -v
python3 -m unittest discover -s tests -p 'test_traceos_purple.py' -v
python3 -m unittest discover -s tests -p 'test_generated_wrappers.py' -v

echo "[TraceOS] Static preflight PASSED"
