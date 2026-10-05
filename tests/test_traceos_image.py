import contextlib
import importlib.util
import importlib.machinery
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).parent.parent
BIN_DIR = ROOT / "config/includes.chroot/usr/local/bin"
MODULE_PATH = BIN_DIR / "traceos"


def load_module():
    sys.path.insert(0, str(BIN_DIR))
    loader = importlib.machinery.SourceFileLoader("traceos_cli_image_test", str(MODULE_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


class TraceOSImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_run_fd_tool_uses_no_shell_and_inherits_open_fd(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "source.bin"
            path.write_bytes(b"synthetic")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                completed = mock.Mock(returncode=0, stdout="ok\n", stderr="")
                with mock.patch.object(self.mod.subprocess, "run", return_value=completed) as run:
                    result = self.mod._run_fd_tool("file", ["-b"], fd, 5)
                self.assertEqual(result["state"], "ok")
                kwargs = run.call_args.kwargs
                self.assertFalse(kwargs["shell"])
                self.assertEqual(kwargs["pass_fds"], (fd,))
                self.assertIn(f"/proc/self/fd/{fd}", run.call_args.args[0])
            finally:
                os.close(fd)

    def test_non_image_is_rejected_before_optional_analysis_and_source_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evidence.txt"
            original = b"not an image"
            path.write_bytes(original)

            calls = []
            def fake_tool(command, args, fd, timeout, path_first=False):
                calls.append(command)
                return {
                    "state": "ok",
                    "command": command,
                    "exit_code": 0,
                    "stdout": "text/plain\n" if command == "file" else "",
                    "stderr": "",
                }

            output = io.StringIO()
            with mock.patch.object(self.mod, "_run_fd_tool", side_effect=fake_tool):
                with contextlib.redirect_stdout(output):
                    rc = self.mod.analyse_image(path)

            self.assertEqual(rc, 2)
            self.assertEqual(calls, ["file"])
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "not_an_image")
            self.assertTrue(result["source_unchanged"])
            self.assertEqual(path.read_bytes(), original)

    def test_valid_image_reports_local_results_and_same_source_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "synthetic.png"
            original = b"synthetic image bytes"
            path.write_bytes(original)

            def fake_tool(command, args, fd, timeout, path_first=False):
                values = {
                    "file": "image/png\n",
                    "identify": "PNG 8x6",
                    "exiftool": '[{"FileType":"PNG","ImageWidth":8,"ImageHeight":6}]',
                    "tesseract": "Synthetic OCR text\n",
                }
                return {
                    "state": "ok",
                    "command": command,
                    "exit_code": 0,
                    "stdout": values[command],
                    "stderr": "",
                }

            output = io.StringIO()
            with mock.patch.object(self.mod, "_run_fd_tool", side_effect=fake_tool):
                with contextlib.redirect_stdout(output):
                    rc = self.mod.analyse_image(path)

            self.assertEqual(rc, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["mime"], "image/png")
            self.assertEqual(result["dimensions"]["state"], "ok")
            self.assertEqual(result["metadata"]["state"], "ok")
            self.assertEqual(result["ocr"]["state"], "ok")
            self.assertTrue(result["source_unchanged"])
            self.assertEqual(result["sha256_before"], result["sha256_after"])
            self.assertEqual(path.read_bytes(), original)

    def test_source_change_is_detected_after_local_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "synthetic.png"
            path.write_bytes(b"before")

            changed = False
            def fake_tool(command, args, fd, timeout, path_first=False):
                nonlocal changed
                if command == "identify" and not changed:
                    path.write_bytes(b"after")
                    changed = True
                values = {
                    "file": "image/png\n",
                    "identify": "PNG 8x6",
                    "exiftool": "{}",
                    "tesseract": "",
                }
                return {
                    "state": "ok",
                    "command": command,
                    "exit_code": 0,
                    "stdout": values[command],
                    "stderr": "",
                }

            output = io.StringIO()
            with mock.patch.object(self.mod, "_run_fd_tool", side_effect=fake_tool):
                with contextlib.redirect_stdout(output):
                    rc = self.mod.analyse_image(path)

            self.assertEqual(rc, 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "source_changed")
            self.assertFalse(result["source_unchanged"])

    def test_symbolic_link_is_not_accepted_as_image_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "real.png"
            link = root / "link.png"
            target.write_bytes(b"image")
            os.symlink(target, link)
            rc = self.mod.analyse_image(link)
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
