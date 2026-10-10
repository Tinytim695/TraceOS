import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
GUEST = ROOT / "config/includes.chroot/usr/local/sbin/traceos-qemu-cli-e2e"
HOST = ROOT / "scripts/qemu-cli-e2e-smoke.sh"


def load_function(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    node = next(
        item for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name
    )
    isolated = ast.Module(body=[node], type_ignores=[])
    namespace = {"re": re}
    exec(compile(ast.fix_missing_locations(isolated), str(path), "exec"), namespace)
    return namespace[name]


class MsfVenomProbeTests(unittest.TestCase):
    def test_guest_probe_uses_help_not_version_and_never_generates_payload(self):
        tree = ast.parse(GUEST.read_text(encoding="utf-8"), filename=str(GUEST))
        assignment = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "msfvenom_startup"
                    for target in node.targets)
        )
        self.assertIsInstance(assignment.value, ast.Call)
        self.assertEqual(assignment.value.func.id, "tool_version")
        probe_args = [arg.value for arg in assignment.value.args]
        self.assertEqual(probe_args, ["msfvenom-startup", "/usr/local/bin/msfvenom", "--help"])
        self.assertNotIn("--payload", probe_args)
        self.assertNotIn("--out", probe_args)
        self.assertNotIn("-p", probe_args)
        self.assertNotIn("-o", probe_args)

    def test_guest_and_host_require_genuine_help_output(self):
        good = """MsfVenom - a Metasploit standalone payload generator.
Usage: msfvenom [options] <var=val>

Options:
  -p, --payload <payload>
"""
        bad_outputs = [
            "msfvenom: version unknown\n",
            "Usage: msfvenom [options]\n",
            "MsfVenom payload generator\nOptions:\n",
            "Some unrelated tool\nUsage: example\nOptions:\n",
            "",
        ]
        for path in (GUEST, HOST):
            with self.subTest(path=path):
                checker = load_function(path, "valid_msfvenom_help")
                self.assertTrue(checker(good))
                for output in bad_outputs:
                    with self.subTest(output=output):
                        self.assertFalse(checker(output))

    def test_guest_and_host_expect_pinned_upstream_help_exit(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("msfvenom_startup.returncode == 1", guest)
        self.assertIn('exit_code("msfvenom-startup") == 1', host)
        self.assertIn('expected_exit = 1 if label == "msfvenom-startup" else 0', host)

    def test_host_requires_successful_help_exit_and_content(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn('"MSFVENOM_HELP_CONTENT"', host)
        self.assertIn('"MATRIX_MSFVENOM_HELP_OK"', host)
        self.assertIn("valid_msfvenom_help(msfvenom_help_output)", host)

    def test_version_unknown_is_not_accepted_as_help(self):
        for path in (GUEST, HOST):
            with self.subTest(path=path):
                checker = load_function(path, "valid_msfvenom_help")
                self.assertFalse(checker("msfvenom: version unknown"))


    def test_timeout_probe_diagnostics_are_safe_and_bounded(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", guest)
        self.assertIn("os.killpg(p.pid, signal.SIGTERM)", guest)
        self.assertIn("p.communicate(timeout=0.5)", guest)
        self.assertIn("process_group_survived", guest)
        self.assertNotIn("return p.communicate()", guest)
        self.assertIn("Thread.list.each_with_index", guest)
        self.assertIn('for cwd in ("/home/traceos","/opt/traceos-metasploit"):', guest)
        self.assertIn('"metasploit-diagnostics.txt"', guest)
        self.assertIn('"metasploit-diagnostics.txt"', host)

    def test_metasploit_startup_probes_use_pinned_source_directory(self):
        guest = GUEST.read_text(encoding="utf-8")
        for label in ("msfconsole-startup", "msfvenom-startup", "msfdb-startup"):
            line = next(line for line in guest.splitlines() if label in line and "tool_version(" in line)
            self.assertIn('cwd="/opt/traceos-metasploit"', line)


if __name__ == "__main__":
    unittest.main()
