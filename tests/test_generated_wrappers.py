import re
import subprocess
import unittest
from pathlib import Path

HOOK = Path(__file__).parents[1] / "config/hooks/live/0240-traceos-offensive.hook.chroot"

class GeneratedWrapperFixturesTests(unittest.TestCase):
    def test_generated_metasploit_wrappers_have_valid_shell(self):
        source = HOOK.read_text(encoding="utf-8")
        matches = re.findall(
            r"cat > (/usr/local/bin/msf(?:console|venom|db)) <<\x27EOF\x27\n(.*?)\nEOF\n",
            source, re.DOTALL
        )
        self.assertEqual(
            {path for path, _ in matches},
            {"/usr/local/bin/msfconsole", "/usr/local/bin/msfvenom", "/usr/local/bin/msfdb"},
        )
        for path, body in matches:
            self.assertIn('MSF_BUNDLER="2.6.7"', body, path)
            self.assertIn('gem "bundler", ENV.fetch("MSF_BUNDLER")', body, path)
            self.assertIn("$0 = program; load program", body, path)
            self.assertIn("BUNDLE_GEMFILE=/opt/traceos-metasploit/Gemfile", body, path)
            self.assertIn("TRACEOS_MSF_BOOTSNAP_READONLY=1", body, path)
            self.assertIn(path.replace("/usr/local/bin/", "/opt/traceos-metasploit/"), body, path)
            result = subprocess.run(
                ["bash", "-n"], input=body, text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 0, f"{path}: {result.stderr}")

if __name__ == "__main__":
    unittest.main()
