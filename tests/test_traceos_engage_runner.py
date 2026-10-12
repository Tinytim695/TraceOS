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
    wanted = {"_write_log", "_process_group_exists", "_stop_process_group", "_run_steps"}
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
