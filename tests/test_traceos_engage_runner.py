import ast
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "config/includes.chroot/usr/local/bin/traceos-engage"


def load_runner_functions():
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"), filename=str(RUNNER))
    wanted = {
        "_write_log",
        "_process_group_exists",
        "_process_group_has_live_member",
        "_stop_process_group",
        "_run_steps",
        "_write_canary",
    }
    nodes = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    missing = wanted - {node.name for node in nodes}
    if missing:
        raise AssertionError(f"missing runner functions: {sorted(missing)}")
    namespace = {
        "os": os,
        "selectors": selectors,
        "signal": signal,
        "subprocess": subprocess,
        "sys": sys,
        "time": time,
        "ACTIVE_STEP_PROCESS": None,
        "Path": Path,
        "CANARY_NAME": "purple-canary.txt",
        "CANARY_TEXT": "TraceOS-PURPLE-CANARY\n",
        "CaseError": Exception,
        "STORE": None,
        "die": lambda message: (_ for _ in ()).throw(SystemExit(2)),
    }
    isolated = ast.Module(body=nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(isolated), str(RUNNER), "exec"), namespace)
    return namespace


class TraceOSEngagementRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.functions = load_runner_functions()

    def test_partial_line_does_not_block_the_execution_deadline(self):
        run_steps = self.functions["_run_steps"]
        started = time.monotonic()
        status = run_steps(
            [{
                "name": "partial-output-timeout",
                "argv": [
                    sys.executable,
                    "-c",
                    "import os,time; os.write(1,b'partial-without-newline'); time.sleep(30)",
                ],
                "timeout": 0.4,
            }]
        )
        elapsed = time.monotonic() - started
        self.assertEqual(status, 124)
        self.assertLess(elapsed, 3.0)

    def test_timeout_kills_descendant_processes(self):
        run_steps = self.functions["_run_steps"]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child-survived"
            script = (
                "import os,time\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    time.sleep(1.2)\n"
                f"    open({str(marker)!r}, 'w').write('survived')\n"
                "    os._exit(0)\n"
                "time.sleep(30)\n"
            )
            started = time.monotonic()
            status = run_steps(
                [{
                    "name": "descendant-cleanup-timeout",
                    "argv": [sys.executable, "-c", script],
                    "timeout": 0.4,
                }]
            )
            elapsed = time.monotonic() - started
            self.assertEqual(status, 124)
            self.assertLess(elapsed, 3.0)
            time.sleep(1.4)
            self.assertFalse(marker.exists())

    def test_successful_leader_cannot_leave_a_background_child_running(self):
        run_steps = self.functions["_run_steps"]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "detached-child-ran"
            script = (
                "import os,time\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    os.close(1)\n"
                "    os.close(2)\n"
                "    time.sleep(1.2)\n"
                f"    open({str(marker)!r}, 'w').write('survived')\n"
                "    os._exit(0)\n"
                "os._exit(0)\n"
            )
            status = run_steps(
                [{
                    "name": "background-child",
                    "argv": [sys.executable, "-c", script],
                    "timeout": 3,
                }]
            )
            self.assertEqual(status, 125)
            time.sleep(1.4)
            self.assertFalse(marker.exists())

    def test_canary_refuses_to_overwrite_existing_case_note(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            notes = case / "notes"
            notes.mkdir()
            canary = notes / "purple-canary.txt"
            original = "operator notes must survive\n"
            canary.write_text(original, encoding="utf-8")

            class FakeStore:
                def current(self):
                    return type("CaseRecord", (), {"path": case})()

                def open_required_dir(self, case_path, name):
                    self.assert_is_notes(case_path, name)
                    return os.open(
                        notes,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )

                @staticmethod
                def assert_is_notes(case_path, name):
                    if case_path != case or name != "notes":
                        raise AssertionError("unexpected case notes directory")

            self.functions["STORE"] = FakeStore()
            with self.assertRaises(SystemExit):
                self.functions["_write_canary"]()
            self.assertEqual(canary.read_text(encoding="utf-8"), original)

    def test_canary_creates_a_new_private_case_note(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            notes = case / "notes"
            notes.mkdir()

            class FakeStore:
                def current(self):
                    return type("CaseRecord", (), {"path": case})()

                def open_required_dir(self, case_path, name):
                    if case_path != case or name != "notes":
                        raise AssertionError("unexpected case notes directory")
                    return os.open(
                        notes,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )

            self.functions["STORE"] = FakeStore()
            path = Path(self.functions["_write_canary"]())
            self.assertEqual(path, notes / "purple-canary.txt")
            self.assertEqual(path.read_text(encoding="utf-8"), "TraceOS-PURPLE-CANARY\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_normal_step_still_streams_and_returns_its_exit_code(self):
        run_steps = self.functions["_run_steps"]
        status = run_steps(
            [{
                "name": "normal-exit",
                "argv": [sys.executable, "-c", "print('synthetic ok'); raise SystemExit(7)"],
                "timeout": 3,
            }]
        )
        self.assertEqual(status, 7)


if __name__ == "__main__":
    unittest.main()
