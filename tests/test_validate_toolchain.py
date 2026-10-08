import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/validate-toolchain.sh"

class ValidateToolchainResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "root"
        for d in ("usr/bin", "usr/sbin", "usr/local/bin"):
            (self.root / d).mkdir(parents=True)
        self.external = self.base / "outside"
        self.external.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def executable(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)

    def resolve(self):
        env = os.environ.copy()
        env["TRACEOS_VALIDATE_CMD"] = "tool"
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.root)],
            env=env, text=True, capture_output=True
        )

    def test_host_only_absolute_link_is_not_followed(self):
        (self.root / "usr/bin/tool").symlink_to("/usr/bin/sh")
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_valid_guest_absolute_link(self):
        real = self.root / "usr/local/bin/tool-real"
        self.executable(real)
        (self.root / "usr/bin/tool").symlink_to("/usr/local/bin/tool-real")
        self.assertEqual(self.resolve().returncode, 0)

    def test_chained_links(self):
        real = self.root / "usr/local/bin/tool-real"
        self.executable(real)
        (self.root / "usr/bin/tool").symlink_to("../local/bin/link1")
        (self.root / "usr/local/bin/link1").symlink_to("tool-real")
        self.assertEqual(self.resolve().returncode, 0)

    def test_traversal_is_rejected(self):
        real = self.external / "real"
        self.executable(real)
        (self.root / "usr/bin/tool").symlink_to("../../../outside/real")
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_loop_is_rejected(self):
        (self.root / "usr/bin/tool").symlink_to("tool-loop")
        (self.root / "usr/bin/tool-loop").symlink_to("tool")
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_directory_as_command_is_rejected(self):
        target = self.root / "usr/bin/tool"
        target.mkdir()
        target.chmod(0o755)
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_fifo_as_command_is_rejected(self):
        os.mkfifo(self.root / "usr/bin/tool", 0o600)
        self.assertNotEqual(self.resolve().returncode, 0)

if __name__ == "__main__":
    unittest.main()
