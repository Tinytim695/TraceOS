import hashlib
import os
import pathlib
import stat
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import FrozenInstanceError
from unittest import mock

LIB = pathlib.Path(__file__).parents[1] / "config/includes.chroot/usr/local/lib/traceos"
sys.path.insert(0, str(LIB))

import actions
import investigation


class _PermissiveTestAdapter:
    key = "fake"
    display_name = "Fake"
    command = "fake"
    purpose = "deterministic test adapter"
    network = False

    def available(self):
        return True

    def version_argv(self):
        return [self.command, "--version"]

    def validate_target(self, target):
        return target

    def build_argv(self, target):
        return [self.command, target]

    def parse_result(self, stdout, stderr, exit_code):
        if not stdout:
            raise ValueError("empty fake result")
        return {"kind": "fake", "status": "RESULT"}


class ActionRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{self.root}{os.pathsep}{self.original_path}"

    def tearDown(self):
        os.environ["PATH"] = self.original_path
        self.temp.cleanup()

    def fake(self, name, body):
        path = self.root / name
        path.write_text(
            "#!/bin/sh\nset -eu\n" + body + "\n",
            encoding="utf-8",
        )
        path.chmod(stat.S_IRWXU)
        return path

    def request(
        self,
        adapter="whois",
        target="example.com",
        authorization=actions.CONFIRMED,
        scope=None,
        **kwargs,
    ):
        return actions.ActionRequest.create(
            adapter,
            target,
            scope=scope or actions.ActionScope("passive_lookup", target),
            authorization_state=authorization,
            **kwargs,
        )

    def patch_adapter(self, adapter):
        patcher = mock.patch.dict(investigation.ADAPTERS, {adapter.key: adapter})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_action_does_not_execute_before_start(self):
        tool = self.fake(
            "whois",
            'touch "$(dirname "$0")/ran"; '
            'printf "Domain Name: X\\n"',
        )
        request = self.request()
        self.assertFalse((self.root / "ran").exists())
        result = actions.ActionRunner().execute(request)
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertTrue((tool.parent / "ran").exists())

    def test_invalid_target_never_starts_child(self):
        tool = self.fake("whois", 'touch "$(dirname "$0")/ran"')
        result = actions.ActionRunner().execute(
            self.request(target="-example.com")
        )
        self.assertEqual(result.state, actions.INVALID_INPUT)
        self.assertEqual(result.error_class, "invalid_target")
        self.assertFalse((tool.parent / "ran").exists())

    def test_scope_mismatch_never_starts_child(self):
        tool = self.fake("whois", 'touch "$(dirname "$0")/ran"')
        scope = actions.ActionScope("passive_lookup", "other.example")
        result = actions.ActionRunner().execute(self.request(scope=scope))
        self.assertEqual(result.state, actions.INVALID_INPUT)
        self.assertEqual(result.error_class, "scope_mismatch")
        self.assertFalse((tool.parent / "ran").exists())

    def test_network_action_requires_confirmation(self):
        tool = self.fake("whois", 'touch "$(dirname "$0")/ran"')
        result = actions.ActionRunner().execute(
            self.request(authorization=actions.REQUIRED)
        )
        self.assertEqual(result.state, actions.INVALID_INPUT)
        self.assertEqual(result.error_class, "authorization_required")
        self.assertFalse((tool.parent / "ran").exists())

    def test_target_is_one_argv_argument(self):
        tool = self.fake(
            "whois",
            'printf "Domain Name: EXAMPLE.COM\\n"; '
            'printf "%s\\n" "$#" "$1" > "$(dirname "$0")/argv"',
        )
        result = actions.ActionRunner().execute(
            self.request(target="münich.example")
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(
            (tool.parent / "argv").read_text(encoding="utf-8").splitlines(),
            ["1", "xn--mnich-kva.example"],
        )

    def test_shell_metacharacters_are_not_interpreted(self):
        self.patch_adapter(_PermissiveTestAdapter())
        tool = self.fake(
            "fake",
            'printf "%s\\n" "$1" > "$(dirname "$0")/argv"; '
            'printf "ok\\n"',
        )
        target = "$(touch should_not_exist)"
        result = actions.ActionRunner().execute(
            self.request(
                adapter="fake",
                target=target,
                authorization=actions.NOT_REQUIRED,
            )
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual((tool.parent / "argv").read_text().strip(), target)
        self.assertFalse((self.root / "should_not_exist").exists())

    def test_credential_url_is_rejected(self):
        tool = self.fake("whois", 'touch "$(dirname "$0")/ran"')
        result = actions.ActionRunner().execute(
            self.request(target="https://user:pass@example.com")
        )
        self.assertEqual(result.state, actions.INVALID_INPUT)
        self.assertFalse((tool.parent / "ran").exists())

    def test_missing_executable_returns_unavailable(self):
        adapter = investigation.BasicLookupAdapter(
            "missing",
            "Missing",
            "definitely-not-installed-traceos-test-tool",
            "test",
            False,
            (),
        )
        self.patch_adapter(adapter)
        result = actions.ActionRunner().execute(
            actions.ActionRequest.create(
                "missing",
                "example.com",
                scope=actions.ActionScope("passive_lookup", "example.com"),
                authorization_state=actions.NOT_REQUIRED,
            )
        )
        self.assertEqual(result.state, actions.UNAVAILABLE)
        self.assertIsNone(result.start_time_utc)

    def test_nonzero_exit_returns_failed(self):
        self.fake("whois", "exit 7")
        result = actions.ActionRunner().execute(self.request())
        self.assertEqual(result.state, actions.FAILED)
        self.assertEqual(result.exit_code, 7)
        self.assertEqual(result.error_class, "tool_error")

    def test_timeout_returns_timed_out(self):
        self.fake("whois", "sleep 5")
        result = actions.ActionRunner(grace_seconds=0.1).execute(
            self.request(timeout_seconds=0.2)
        )
        self.assertEqual(result.state, actions.TIMED_OUT)
        self.assertEqual(result.termination_reason, "timeout")

    def _group_test_body(self):
        script = r'''
import os
import signal
import subprocess
import sys
import time

root = os.path.dirname(__file__)
sentinel = os.path.join(root, "sentinel")
parent_pid = os.path.join(root, "parent.pid")
child_pid = os.path.join(root, "child.pid")


def child_exit(signum, frame):
    del signum, frame
    try:
        os.unlink(sentinel)
    except FileNotFoundError:
        pass
    raise SystemExit(0)


child = None


def parent_exit(signum, frame):
    del signum, frame
    try:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            child.wait(timeout=1.0)
    except Exception:
        try:
            if child is not None and child.poll() is None:
                child.kill()
        except Exception:
            pass
    try:
        os.unlink(sentinel)
    except FileNotFoundError:
        pass
    raise SystemExit(0)


def run_child():
    signal.signal(signal.SIGTERM, child_exit)
    signal.signal(signal.SIGINT, child_exit)
    with open(sentinel, "w", encoding="utf-8") as handle:
        handle.write("child-running")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    if sys.argv[-1] == "child":
        run_child()
    signal.signal(signal.SIGTERM, parent_exit)
    signal.signal(signal.SIGINT, parent_exit)
    child = subprocess.Popen([sys.executable, __file__, "child"])
    with open(child_pid, "w", encoding="utf-8") as handle:
        handle.write(str(child.pid))
    while child.poll() is None:
        time.sleep(1)
'''
        return (
            'cat > "$(dirname "$0")/group_helper.py" <<\'PY\'\n'
            + script
            + '\nPY\n'
            + 'exec python3 "$(dirname "$0")/group_helper.py"'
        )

    def _assert_pid_gone(self, pid_path):
        pid = int(pid_path.read_text(encoding="utf-8").strip())
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                self.fail("process still exists but cannot be inspected")
            time.sleep(0.05)
        self.fail(f"process {pid} still exists after group termination")

    def test_timeout_kills_process_group(self):
        tool = self.fake("whois", self._group_test_body())
        result = actions.ActionRunner(grace_seconds=0.15).execute(
            self.request(timeout_seconds=0.3)
        )
        self.assertEqual(result.state, actions.TIMED_OUT)
        time.sleep(0.1)
        self.assertFalse((tool.parent / "sentinel").exists())
        self._assert_pid_gone(tool.parent / "parent.pid")

    def test_cancel_returns_cancelled(self):
        self.fake("whois", "sleep 5")
        cancel = threading.Event()
        holder = {}

        def worker():
            holder["result"] = actions.ActionRunner(
                grace_seconds=0.1
            ).execute(self.request(timeout_seconds=5), cancel)

        thread = threading.Thread(target=worker)
        thread.start()
        time.sleep(0.2)
        cancel.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(holder["result"].state, actions.CANCELLED)

    def test_cancel_kills_process_group(self):
        tool = self.fake("whois", self._group_test_body())
        cancel = threading.Event()
        holder = {}

        def worker():
            holder["result"] = actions.ActionRunner(
                grace_seconds=0.15
            ).execute(self.request(timeout_seconds=5), cancel)

        thread = threading.Thread(target=worker)
        thread.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not (
            tool.parent / "sentinel"
        ).exists():
            time.sleep(0.03)
        self.assertTrue((tool.parent / "sentinel").exists())
        cancel.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(holder["result"].state, actions.CANCELLED)
        time.sleep(0.1)
        self.assertFalse((tool.parent / "sentinel").exists())
        self._assert_pid_gone(tool.parent / "parent.pid")

    def test_stdout_and_stderr_are_separate(self):
        self.fake("whois", 'printf "out"; printf "err" >&2')
        result = actions.ActionRunner().execute(self.request())
        self.assertEqual(result.state, actions.PARSE_FAILED)
        self.assertEqual(result.stdout_preview, "out")
        self.assertEqual(result.stderr_preview, "err")

    def test_large_output_is_bounded(self):
        self.fake(
            "whois",
            'i=0; while [ "$i" -lt 20000 ]; do '
            'printf x; i=$((i+1)); done',
        )
        result = actions.ActionRunner().execute(
            self.request(output_limit_bytes=1024)
        )
        self.assertEqual(result.state, actions.PARSE_FAILED)
        self.assertLessEqual(len(result.stdout_preview.encode()), 1024)
        self.assertGreater(result.stdout_byte_count, 1024)
        self.assertTrue(result.stdout_truncated)

    def test_large_output_is_drained(self):
        self.fake(
            "whois",
            'printf "field: value\\n"; '
            'i=0; while [ "$i" -lt 50000 ]; do '
            'printf x; i=$((i+1)); done',
        )
        result = actions.ActionRunner().execute(
            self.request(timeout_seconds=5, output_limit_bytes=1024)
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.stdout_byte_count, 50013)
        self.assertLessEqual(len(result.stdout_preview.encode()), 1024)
        self.assertTrue(result.stdout_truncated)

    def test_malformed_result_is_parse_failed(self):
        self.fake("whois", 'printf "MALFORMED OUTPUT\\n"')
        result = actions.ActionRunner().execute(self.request())
        self.assertEqual(result.state, actions.PARSE_FAILED)
        self.assertEqual(result.error_class, "parser_failure")

    def test_result_does_not_write_case_or_evidence(self):
        case = self.root / "case"
        (case / "evidence").mkdir(parents=True)
        (case / "hashes").mkdir()
        before = sorted(str(path.relative_to(case)) for path in case.rglob("*"))
        self.fake("whois", 'printf "Domain Name: EXAMPLE.COM\\n"')
        result = actions.ActionRunner().execute(self.request(case_id="case-1"))
        after = sorted(str(path.relative_to(case)) for path in case.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual(result.state, actions.COMPLETED)

    def test_dns_answer_is_structured(self):
        self.fake(
            "dig",
            "cat <<'EOF'\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
            ";; flags: qr; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n"
            "example.com. 60 IN A 127.0.0.1\n"
            "EOF",
        )
        result = actions.ActionRunner().execute(
            self.request(adapter="dns")
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.parsed_result["status"], "ANSWER")
        self.assertEqual(result.parsed_result["answer_count"], 1)

    def test_dns_nxdomain_is_distinct(self):
        self.fake(
            "dig",
            "cat <<'EOF'\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n"
            ";; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n"
            "EOF",
        )
        result = actions.ActionRunner().execute(
            self.request(adapter="dns")
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.parsed_result["status"], "NXDOMAIN")

    def test_dns_tool_error_is_distinct(self):
        self.fake(
            "dig",
            "cat <<'EOF'\n"
            ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1\n"
            ";; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n"
            "EOF",
        )
        result = actions.ActionRunner().execute(
            self.request(adapter="dns")
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.parsed_result["status"], "TOOL_ERROR")
        self.assertEqual(result.parsed_result["rcode"], "SERVFAIL")

    def test_whois_result_is_structured(self):
        self.fake(
            "whois",
            'printf "Domain Name: EXAMPLE.COM\\n'
            'Registry Domain ID: 123\\n"',
        )
        result = actions.ActionRunner().execute(self.request())
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.parsed_result["kind"], "whois")
        self.assertEqual(result.parsed_result["field_count"], 2)
        self.assertEqual(result.parsed_result["line_count"], 2)

    def test_action_request_is_immutable_and_uses_one_generated_id(self):
        request = self.request()
        self.assertIsInstance(request.action_id, uuid.UUID)
        with self.assertRaises(FrozenInstanceError):
            request.action_id = uuid.uuid4()

    def test_action_result_is_immutable(self):
        self.fake("whois", 'printf "Domain Name: EXAMPLE.COM\\n"')
        result = actions.ActionRunner().execute(self.request())
        with self.assertRaises(FrozenInstanceError):
            result.state = actions.FAILED

    def test_result_hashes_match_complete_drained_bytes(self):
        stdout = b"Domain Name: EXAMPLE.COM\n"
        stderr = b"diagnostic\n"
        self.fake(
            "whois",
            'printf "Domain Name: EXAMPLE.COM\\n"; '
            'printf "diagnostic\\n" >&2',
        )
        result = actions.ActionRunner().execute(self.request())
        self.assertEqual(
            result.stdout_sha256,
            hashlib.sha256(stdout).hexdigest(),
        )
        self.assertEqual(
            result.stderr_sha256,
            hashlib.sha256(stderr).hexdigest(),
        )
        self.assertEqual(result.stdout_byte_count, len(stdout))
        self.assertEqual(result.stderr_byte_count, len(stderr))

    def test_cancel_before_start_never_spawns(self):
        tool = self.fake("whois", 'touch "$(dirname "$0")/ran"')
        cancel = threading.Event()
        cancel.set()
        result = actions.ActionRunner().execute(self.request(), cancel)
        self.assertEqual(result.state, actions.CANCELLED)
        self.assertEqual(
            result.termination_reason,
            "cancelled_before_start",
        )
        self.assertFalse((tool.parent / "ran").exists())

    def test_stderr_large_output_is_drained(self):
        self.fake(
            "whois",
            'printf "Domain Name: EXAMPLE.COM\\n"; '
            'i=0; while [ "$i" -lt 50000 ]; do '
            'printf e >&2; i=$((i+1)); done',
        )
        result = actions.ActionRunner().execute(
            self.request(timeout_seconds=5, output_limit_bytes=1024)
        )
        self.assertEqual(result.state, actions.COMPLETED)
        self.assertEqual(result.stderr_byte_count, 50000)
        self.assertTrue(result.stderr_truncated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
