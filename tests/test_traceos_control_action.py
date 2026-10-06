import importlib.util
import pathlib
import queue
import threading
import unittest
import uuid
from unittest import mock


MODULE = pathlib.Path(__file__).parents[1] / "config/includes.chroot/usr/local/bin/traceos-control"


def load_module():
    spec = importlib.util.spec_from_file_location("traceos_control_action_tests", MODULE)
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

    def test_worker_uses_action_runner_and_queues_result(self):
        app = self._app()
        request = self._request()
        cancel_event = threading.Event()
        result = mock.Mock()
        with mock.patch.object(self.mod.ActionRunner) as runner_cls:
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


if __name__ == "__main__":
    unittest.main()
