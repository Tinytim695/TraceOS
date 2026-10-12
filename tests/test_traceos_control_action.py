import importlib.machinery
import types
import importlib.util
import os
import pathlib
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock


MODULE = pathlib.Path(__file__).parents[1] / "config/includes.chroot/usr/local/bin/traceos-control"
LIB = MODULE.parents[1] / "lib" / "traceos"


def load_module():
    # The build runner does not install tkinter. Stub only the GUI modules
    # needed to import the real control-centre source for lifecycle tests.
    tk_stub = types.ModuleType("tkinter")
    tk_stub.Tk = object
    tk_stub.Event = object
    tk_stub.Text = object
    for name in ("Frame", "Label", "Button", "Entry", "StringVar"):
        setattr(tk_stub, name, object)
    tk_stub.END = "end"
    tk_stub.NORMAL = "normal"
    tk_stub.DISABLED = "disabled"
    filedialog_stub = types.SimpleNamespace()
    messagebox_stub = types.SimpleNamespace()
    messagebox_stub.askyesno = lambda *args, **kwargs: False
    messagebox_stub.showerror = lambda *args, **kwargs: None
    messagebox_stub.showinfo = lambda *args, **kwargs: None
    messagebox_stub.showwarning = lambda *args, **kwargs: None
    ttk_stub = types.SimpleNamespace()
    tk_stub.filedialog = filedialog_stub
    tk_stub.messagebox = messagebox_stub
    tk_stub.ttk = ttk_stub
    for name, value in (
        ("tkinter", tk_stub),
        ("tkinter.filedialog", filedialog_stub),
        ("tkinter.messagebox", messagebox_stub),
        ("tkinter.ttk", ttk_stub),
    ):
        sys.modules[name] = value

    if str(LIB) not in sys.path:
        sys.path.insert(0, str(LIB))

    loader = importlib.machinery.SourceFileLoader("traceos_control_action_tests", str(MODULE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ControlActionLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def _request(self):
        return self.mod.create_basic_lookup_request(
            "whois",
            "example.com",
            authorization_state=self.mod.CONFIRMED,
        )

    def _app(self):
        app = self.mod.TraceOSApp.__new__(self.mod.TraceOSApp)
        app.root = mock.Mock()
        app.active_process = None
        app.active_action_id = None
        app.active_action_cancel = None
        app.active_job_label = None
        app.active_job_kind = None
        app.active_job_attempt = None
        app.action_queue = queue.Queue()
        app.output_widget = None
        app.job_output = ""
        app._trace_diag = mock.Mock()
        return app

    def test_page_helpers_never_spawn(self):
        with mock.patch.object(self.mod, "ActionRunner") as runner:
            self.assertFalse(self.mod.action_result_matches(None, mock.Mock(action_id=uuid.uuid4())))
            runner.assert_not_called()

    def test_start_without_confirmation_does_not_start_worker(self):
        app = self._app()
        with mock.patch.object(self.mod.messagebox, "askyesno", return_value=False), \
             mock.patch.object(self.mod.threading, "Thread") as thread:
            app.start_basic_lookup_action("whois", "example.com")
        thread.assert_not_called()
        self.assertIsNone(app.active_action_id)

    def test_invalid_target_does_not_start_worker_or_prompt(self):
        app = self._app()
        with mock.patch.object(self.mod.messagebox, "askyesno", return_value=True) as ask, \
             mock.patch.object(self.mod.threading, "Thread") as thread:
            app.start_basic_lookup_action("whois", "http://example.com")
        ask.assert_not_called()
        thread.assert_not_called()
        self.assertIsNone(app.active_action_id)

    def test_start_creates_confirmed_action_request_and_worker(self):
        app = self._app()
        request = self._request()
        thread_instance = mock.Mock()
        with mock.patch.object(self.mod.messagebox, "askyesno", return_value=True), \
             mock.patch.object(self.mod, "create_basic_lookup_request", return_value=request) as factory, \
             mock.patch.object(self.mod.threading, "Thread", return_value=thread_instance) as thread:
            app.start_basic_lookup_action("whois", "example.com")
        factory.assert_called_once_with(
            "whois",
            "example.com",
            authorization_state=self.mod.CONFIRMED,
        )
        self.assertEqual(app.active_action_id, request.action_id)
        thread.assert_called_once()
        thread_instance.start.assert_called_once_with()
        app.root.after.assert_called_once()

    def test_action_messages_use_real_newlines(self):
        app = self._app()
        request = self._request()
        thread_instance = mock.Mock()
        with mock.patch.object(self.mod.messagebox, "askyesno", return_value=True) as ask, \
             mock.patch.object(self.mod, "create_basic_lookup_request", return_value=request), \
             mock.patch.object(self.mod.threading, "Thread", return_value=thread_instance):
            app.start_basic_lookup_action("whois", "example.com")
        prompt = ask.call_args.args[1]
        self.assertIn("\n\n", prompt)
        self.assertNotIn("\\n", prompt)
        self.assertIn("\n", app.job_output)
        self.assertNotIn("\\n", app.job_output)

    def test_worker_uses_action_runner_and_queues_result(self):
        app = self._app()
        request = self._request()
        cancel_event = threading.Event()
        result = mock.Mock()
        with mock.patch.object(self.mod, "ActionRunner") as runner_cls:
            runner_cls.return_value.execute.return_value = result
            app._action_worker(request, cancel_event)
        runner_cls.assert_called_once_with()
        runner_cls.return_value.execute.assert_called_once_with(request, cancel_event=cancel_event)
        self.assertIs(app.action_queue.get_nowait(), result)

    def test_stale_result_is_not_current(self):
        active = uuid.uuid4()
        stale = mock.Mock(action_id=uuid.uuid4())
        current = mock.Mock(action_id=active)
        self.assertFalse(self.mod.action_result_matches(active, stale))
        self.assertTrue(self.mod.action_result_matches(active, current))

    def test_structured_result_render_contains_state_and_parser_fields(self):
        result = mock.Mock(
            action_id=uuid.uuid4(),
            tool="whois",
            state="COMPLETED",
            exit_code=0,
            termination_reason=None,
            error_class=None,
            parsed_result={
                "kind": "whois",
                "status": "RESULT",
                "field_count": 3,
                "line_count": 4,
            },
            stdout_preview="Domain Name: example.com\n",
            stderr_preview="",
            stdout_byte_count=24,
            stderr_byte_count=0,
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
        )
        rendered = self.mod.format_basic_lookup_result(result)
        self.assertIn("State: COMPLETED", rendered)
        self.assertIn("Status: RESULT", rendered)
        self.assertIn("Field count: 3", rendered)
        self.assertIn("STDOUT (bounded preview)", rendered)
        self.assertIn("STDERR (bounded preview)", rendered)

    def test_purple_canary_preview_does_not_require_playbook_steps(self):
        preview = self.mod.format_engagement_preview("purple-canary", [])
        self.assertIn("notes/purple-canary.txt", preview)
        self.assertIn("YARA", preview)
        self.assertIn("detected or missed", preview)

    def test_regular_engagement_preview_formats_argv(self):
        preview = self.mod.format_engagement_preview(
            "nmap-quick",
            [{"argv": ["nmap", "-sT", "127.0.0.1"]}],
        )
        self.assertEqual(preview, "nmap -sT 127.0.0.1")

    def test_regular_engagement_preview_rejects_empty_steps(self):
        with self.assertRaises(ValueError):
            self.mod.format_engagement_preview("missing-steps", [])

    def test_poll_job_ignores_stale_output_and_completion_tokens(self):
        app = self.mod.TraceOSApp.__new__(self.mod.TraceOSApp)
        app.root = mock.Mock()
        app.active_process = mock.Mock()
        app.active_process.poll.return_value = 0
        app.active_job_token = "current-task"
        app.active_job_label = "current"
        app.active_job_kind = None
        app.active_job_attempt = None
        app.output_queue = queue.Queue()
        app.output_widget = None
        app.job_output = "starting current task\n"
        app._trace_diag = mock.Mock()
        app.output_queue.put(("old-task", "STALE OUTPUT\n"))
        app.output_queue.put(("old-task", None))
        app.output_queue.put(("current-task", "CURRENT OUTPUT\n"))
        app.output_queue.put(("current-task", None))

        app.poll_job()

        self.assertNotIn("STALE OUTPUT", app.job_output)
        self.assertIn("CURRENT OUTPUT", app.job_output)
        self.assertIsNone(app.active_process)
        self.assertIsNone(app.active_job_token)

    def test_poll_job_reschedules_after_leader_exit_until_reader_sentinel(self):
        app = self.mod.TraceOSApp.__new__(self.mod.TraceOSApp)
        app.root = mock.Mock()
        app.active_process = mock.Mock()
        app.active_process.poll.return_value = 0
        app.active_job_token = "task-token"
        app.active_job_label = "quick task"
        app.active_job_kind = None
        app.active_job_attempt = None
        app.output_queue = queue.Queue()
        app.output_widget = None
        app.job_output = "starting quick task\n"
        app._trace_diag = mock.Mock()

        app.poll_job()

        self.assertIsNotNone(app.active_process)
        self.assertEqual(app.active_job_token, "task-token")
        app.root.after.assert_called_once_with(80, app.poll_job)

    def test_stop_process_group_terminates_descendant_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "child-survived"
            script = (
                "import os, time\n"
                "pid = os.fork()\n"
                "if pid == 0:\n"
                "    time.sleep(1.3)\n"
                f"    open({str(marker)!r}, 'w').write('survived')\n"
                "    os._exit(0)\n"
                "time.sleep(30)\n"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                self.assertTrue(
                    self.mod.terminate_process_group(
                        process, term_timeout=0.1, kill_timeout=2
                    )
                )
                time.sleep(1.5)
                self.assertFalse(marker.exists())
            finally:
                if process.poll() is None:
                    self.mod.terminate_process_group(
                        process, term_timeout=0.1, kill_timeout=2
                    )

    def test_investigation_save_is_unavailable_and_does_not_stage_evidence(self):
        app = self.mod.TraceOSApp.__new__(self.mod.TraceOSApp)
        app.root = object()
        app.job_output = "synthetic investigation output that must not be vaulted\n"
        with mock.patch.object(self.mod.messagebox, "showinfo") as showinfo, \
                mock.patch.object(self.mod, "capture") as capture, \
                mock.patch.object(self.mod.Path, "write_text") as write_text, \
                mock.patch.object(self.mod.Path, "mkdir") as mkdir:
            app.save_investigation_output()
        showinfo.assert_called_once()
        self.assertIn("unavailable", showinfo.call_args.args[1].lower())
        capture.assert_not_called()
        write_text.assert_not_called()
        mkdir.assert_not_called()


if __name__ == "__main__":
    unittest.main()
