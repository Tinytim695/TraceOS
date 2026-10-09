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
    def test_guest_probe_uses_help_not_version(self):
        tree = ast.parse(GUEST.read_text(encoding="utf-8"), filename=str(GUEST))
        assignment = next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "msfvenom_startup"
                    for target in node.targets)
        )
        self.assertIsInstance(assignment.value, ast.Call)
        self.assertEqual(assignment.value.func.id, "tool_version")
        self.assertEqual(
            [arg.value for arg in assignment.value.args],
            ["msfvenom-startup", "/usr/local/bin/msfvenom", "--help"],
        )

    def test_guest_and_host_require_genuine_help_output(self):
        good = (
            "MsfVenom - a Metasploit standalone payload generator.\\n"
            "Usage: msfvenom [options] <var=val>\\n\\n"
            "Options:\\n  -p, --payload <payload>\\n"
        )
        bad_outputs = [
            "msfvenom: version unknown\\n",
            "Usage: msfvenom [options]\\n",
            "MsfVenom payload generator\\nOptions:\\n",
            "Some unrelated tool\\nUsage: example\\nOptions:\\n",
            "",
        ]
        for path in (GUEST, HOST):
            with self.subTest(path=path):
                checker = load_function(path, "valid_msfvenom_help")
                self.assertTrue(checker(good))
                for output in bad_outputs:
                    with self.subTest(output=output):
                        self.assertFalse(checker(output))

    def test_guest_matrix_and_startup_gate_use_help_validation(self):
        source = GUEST.read_text(encoding="utf-8")
        self.assertIn('f"MSFVENOM_HELP_OK={\\'yes\\' if msfvenom_help_ok else \\'no\\'}"', source)
        self.assertIn("    msfvenom_help_ok,", source)
        host = HOST.read_text(encoding="utf-8")
        self.assertIn('"MSFVENOM_HELP_CONTENT"', host)
        self.assertIn('"MATRIX_MSFVENOM_HELP_OK"', host)


if __name__ == "__main__":
    unittest.main()
