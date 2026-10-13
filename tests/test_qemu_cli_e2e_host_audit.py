import ast
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/qemu-cli-e2e-smoke.sh"


def load_functions(names):
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    wanted = set(names)
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    missing = wanted - {node.name for node in nodes}
    if missing:
        raise AssertionError(f"missing functions: {sorted(missing)}")
    namespace = {"Path": Path, "re": re}
    isolated = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(isolated), str(SCRIPT), "exec"), namespace)
    return namespace


class QemuCliHostAuditTests(unittest.TestCase):
    def test_tamper_audit_requires_two_distinct_sha256_digests(self):
        check = load_functions(["has_hash_mismatch"])["has_hash_mismatch"]
        good = (
            "[FAIL] E20261012T000000Z_sample.txt "
            + "expected=" + "a" * 64 + " actual=" + "b" * 64 + "\n"
        )
        self.assertTrue(check(good))
        spaced_name = (
            "[FAIL] evidence filename with spaces.txt expected="
            + "a" * 64 + " actual=" + "b" * 64 + "\n"
        )
        self.assertTrue(check(spaced_name))
        same = "[FAIL] sample expected=" + "a" * 64 + " actual=" + "a" * 64 + "\n"
        self.assertFalse(check(same))
        missing = "[FAIL] missing or unsafe vault copy: sample\n"
        self.assertFalse(check(missing))
        weak = "tamper expected=changed actual=changed\n"
        self.assertFalse(check(weak))

    def test_serial_reader_handles_appends_split_markers_and_truncation(self):
        read_chunk = load_functions(["read_new_serial_chunk"])["read_new_serial_chunk"]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "serial.log"
            log.write_bytes(b"TRACEOS_CI_E2E_PREFLIGHT=1\nTRACEOS_CI_E2E_STAR")
            offset, tail, first = read_chunk(log, 0, "")
            self.assertIn("TRACEOS_CI_E2E_PREFLIGHT=1", first)
            self.assertNotIn("TRACEOS_CI_E2E_STARTED=1", first)

            with log.open("ab") as handle:
                handle.write(b"TED=1\n")
            offset, tail, second = read_chunk(log, offset, tail)
            self.assertIn("TRACEOS_CI_E2E_STARTED=1", second)

            log.write_bytes(b"TRACEOS_CI_E2E_DONE=1\n")
            offset, tail, third = read_chunk(log, offset, tail)
            self.assertIn("TRACEOS_CI_E2E_DONE=1", third)

    def test_output_directories_create_missing_parent_directories(self):
        ensure_dirs = load_functions(["ensure_output_directories"])["ensure_output_directories"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "artifacts" / "traceos" / "out"
            state = root / "state" / "nested"
            ensure_dirs(output, state)
            self.assertTrue(output.is_dir())
            self.assertTrue(state.is_dir())


if __name__ == "__main__":
    unittest.main()
