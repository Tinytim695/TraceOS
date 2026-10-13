import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
HOOK = ROOT / "config/hooks/live/0205-traceos-recon.hook.chroot"


class ReconHookAmassVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake_amass = Path(self.tmp.name) / "amass"
        self.fake_amass.write_text(
            "#!/bin/sh\n"
            'case "$TRACEOS_FAKE_AMASS_MODE" in\n'
            '  stdout) printf "v5.1.1\\n" ;;\n'
            '  stderr) printf "v5.1.1\\n" >&2 ;;\n'
            '  wrong) printf "v5.2.0\\n" >&2 ;;\n'
            '  failure) printf "synthetic version failure\\n" >&2; exit 7 ;;\n'
            '  *) exit 9 ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        self.fake_amass.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_version_check(self, mode):
        source = HOOK.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^check_amass_version\(\) \{\n.*?^\}",
            source,
        )
        self.assertIsNotNone(match, "hook must define check_amass_version()")
        script = (
            match.group(0)
            + '\ncheck_amass_version "$1" "5.1.1"\n'
        )
        env = os.environ.copy()
        env["TRACEOS_FAKE_AMASS_MODE"] = mode
        return subprocess.run(
            ["sh", "-c", script, "amass-version-test", str(self.fake_amass)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_accepts_version_on_stdout(self):
        result = self.run_version_check("stdout")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("v5.1.1", result.stdout)

    def test_accepts_version_on_stderr(self):
        result = self.run_version_check("stderr")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("v5.1.1", result.stdout)

    def test_rejects_wrong_version(self):
        result = self.run_version_check("wrong")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected version 5.1.1", result.stderr)

    def test_rejects_failed_probe(self):
        result = self.run_version_check("failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version probe failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
