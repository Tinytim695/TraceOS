import ast
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
GUEST = ROOT / "config/includes.chroot/usr/local/sbin/traceos-qemu-cli-e2e"
HOST = ROOT / "scripts/qemu-cli-e2e-smoke.sh"


def load_function(path, name):
    return load_functions(path, [name])[name]


def load_functions(path, names):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    wanted = set(names)
    nodes = [
        item for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in wanted
    ]
    missing = wanted - {node.name for node in nodes}
    if missing:
        raise AssertionError(f"missing functions: {sorted(missing)}")
    isolated = ast.Module(body=nodes, type_ignores=[])
    namespace = {
        "re": re,
        "Path": Path,
        "shutil": shutil,
        "os": os,
        "signal": signal,
        "subprocess": subprocess,
        "time": time,
        "cleanup_details": {},
    }
    exec(compile(ast.fix_missing_locations(isolated), str(path), "exec"), namespace)
    return namespace


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

    def test_msfconsole_version_output_must_be_genuine(self):
        good = "Framework Version: 6.5.6-dev-c6e99d0826\n"
        bad_outputs = [
            "",
            "msfconsole: command failed\n",
            "Framework Version: \n",
            "version unknown\n",
        ]
        for path in (GUEST, HOST):
            with self.subTest(path=path):
                checker = load_function(path, "valid_msfconsole_version")
                self.assertTrue(checker(good))
                for output in bad_outputs:
                    with self.subTest(output=output):
                        self.assertFalse(checker(output))

    def test_msfconsole_timeout_recovery_retains_original_failure(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        self.assertIn('if first_exit == "124":', guest)
        self.assertIn('msfconsole-startup-first-attempt.{suffix}', guest)
        self.assertIn('RECOVERY_RETRY_BEGIN label=msfconsole-startup execution_budget=30s', guest)
        self.assertIn('valid_msfconsole_version(retry_output)', guest)
        self.assertIn('"msfconsole-startup-first-attempt.exit"', host)
        self.assertIn('"MSFCONSOLE_FIRST_TIMEOUT_RETAINED"', host)
        self.assertIn('valid_msfconsole_version(stdout + "\\n" + stderr)', host)


    def test_timeout_preservation_executes_and_copies_all_original_files(self):
        preserve = load_function(GUEST, "preserve_first_attempt_files")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = {
                "stdout": b"first attempt stdout\\n",
                "stderr": b"first attempt stderr\\n",
                "exit": b"124\\n",
            }
            for suffix, payload in expected.items():
                (root / f"msfconsole-startup.{suffix}").write_bytes(payload)

            preserve(root)

            for suffix, payload in expected.items():
                retained = root / f"msfconsole-startup-first-attempt.{suffix}"
                self.assertEqual(retained.read_bytes(), payload)
                self.assertEqual((root / f"msfconsole-startup.{suffix}").read_bytes(), payload)

    def test_timeout_preservation_fails_closed_when_artifact_missing(self):
        preserve = load_function(GUEST, "preserve_first_attempt_files")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "msfconsole-startup.stdout").write_text("original\\n")
            (root / "msfconsole-startup.stderr").write_text("original\\n")
            with self.assertRaises(FileNotFoundError):
                preserve(root)

    def test_timeout_preservation_does_not_keep_partial_copies(self):
        preserve = load_function(GUEST, "preserve_first_attempt_files")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "msfconsole-startup.stderr").write_text("original stderr\n")
            (root / "msfconsole-startup.exit").write_text("124\n")
            with self.assertRaises(FileNotFoundError):
                preserve(root)
            retained = list(root.glob("msfconsole-startup-first-attempt.*"))
            self.assertEqual(retained, [])

    def test_probe_classification_and_recovery_policy(self):
        functions = load_functions(
            GUEST,
            [
                "classify_probe_result",
                "diagnostic_cleanup_blocks_retry",
                "msfconsole_recovery_action",
            ],
        )
        classify = functions["classify_probe_result"]
        blocks = functions["diagnostic_cleanup_blocks_retry"]
        action = functions["msfconsole_recovery_action"]

        self.assertEqual(classify(True, "complete"), "timeout")
        self.assertEqual(classify(True, "process_group_survived"), "cleanup_incomplete")
        self.assertEqual(classify(True, "leader_reap_timeout"), "cleanup_incomplete")
        self.assertEqual(classify(True, "output_drain_timeout"), "cleanup_incomplete")
        self.assertEqual(classify(False, "not_needed"), "application")
        self.assertEqual(classify(False, "complete"), "application")
        self.assertEqual(classify(False, "process_group_survived"), "cleanup_incomplete")

        # A diagnostic timeout whose process group was fully reaped does not
        # block the single recovery retry. Incomplete diagnostic cleanup does.
        self.assertFalse(blocks("complete"))
        self.assertFalse(blocks("not_needed"))
        self.assertTrue(blocks("process_group_survived"))
        self.assertTrue(blocks("leader_reap_timeout"))
        self.assertTrue(blocks("output_drain_timeout"))
        self.assertEqual(action("124", True), "retry")
        self.assertEqual(action("124", False), "skip_diagnostic_cleanup_incomplete")
        self.assertEqual(action("125", True), "skip_initial_cleanup_incomplete")
        self.assertEqual(action("1", True), "skip_not_confirmed_timeout")
        self.assertEqual(action("", False), "skip_not_confirmed_timeout")

    def _reap_group(self, proc):
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)

    def _process_group_members(self, pgid):
        members = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                stat = Path(f"/proc/{entry}/stat").read_text(encoding="utf-8")
            except OSError:
                continue
            marker = stat.rfind(")")
            fields = stat[marker + 2:].split()
            if len(fields) >= 3 and fields[2] == str(pgid):
                members.append(entry)
        return members

    def test_stop_process_group_terminates_real_children(self):
        functions = load_functions(
            GUEST,
            ["process_group_exists", "stop_process_group"],
        )
        functions["cleanup_details"].clear()
        stop = functions["stop_process_group"]
        exists = functions["process_group_exists"]
        proc = subprocess.Popen(
            ["bash", "-c", "sleep 60 & sleep 60 & wait"],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.4)
            pgid = os.getpgid(proc.pid)
            self.assertGreaterEqual(len(self._process_group_members(pgid)), 3)
            started = time.monotonic()
            stop(proc)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 8.0)
            self.assertFalse(exists(pgid))
            self.assertEqual(functions["cleanup_details"][proc.pid]["status"], "complete")
            self.assertEqual(self._process_group_members(pgid), [])
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)
        finally:
            self._reap_group(proc)

    def test_stop_process_group_kills_sigterm_resistant_leader(self):
        functions = load_functions(
            GUEST,
            ["process_group_exists", "stop_process_group"],
        )
        functions["cleanup_details"].clear()
        stop = functions["stop_process_group"]
        proc = subprocess.Popen(
            ["bash", "-c", "trap '' TERM; while true; do sleep 30; done"],
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(0.4)
            self.assertIsNone(proc.poll())
            started = time.monotonic()
            stop(proc)
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 1.0)
            self.assertLess(elapsed, 8.0)
            self.assertEqual(functions["cleanup_details"][proc.pid]["status"], "complete")
            self.assertFalse(functions["process_group_exists"](proc.pid))
            self.assertEqual(self._process_group_members(proc.pid), [])
        finally:
            self._reap_group(proc)

    def test_cleanup_failure_is_not_classified_as_retryable_timeout(self):
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn('if cleanup_status not in ("complete",):', guest)
        self.assertIn('results[label] = 125', guest)
        self.assertIn('msfconsole_recovery_action(', guest)
        self.assertIn('reason=diagnostic_cleanup_incomplete', guest)



if __name__ == "__main__":
    unittest.main()
