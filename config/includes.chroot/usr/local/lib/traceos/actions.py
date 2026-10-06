#!/usr/bin/env python3
"""TraceOS-native action/result execution for bounded, shell-free tool runs."""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

COMPLETED = "COMPLETED"
FAILED = "FAILED"
UNAVAILABLE = "UNAVAILABLE"
INVALID_INPUT = "INVALID_INPUT"
TIMED_OUT = "TIMED_OUT"
CANCELLED = "CANCELLED"
OUTPUT_LIMIT = "OUTPUT_LIMIT"
PARSE_FAILED = "PARSE_FAILED"

NOT_REQUIRED = "NOT_REQUIRED"
REQUIRED = "REQUIRED"
CONFIRMED = "CONFIRMED"

_ACTION_STATES = frozenset(
    {
        COMPLETED,
        FAILED,
        UNAVAILABLE,
        INVALID_INPUT,
        TIMED_OUT,
        CANCELLED,
        OUTPUT_LIMIT,
        PARSE_FAILED,
    }
)
_AUTHORIZATION_STATES = frozenset({NOT_REQUIRED, REQUIRED, CONFIRMED})
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class ActionScope:
    """Minimal passive lookup scope for the first TraceOS action slice."""

    mode: str
    target: str
    resolver: str | None = None


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """Immutable operator request. Construction never starts a process."""

    schema_version: int
    action_id: uuid.UUID = field(default_factory=uuid.uuid4)
    adapter_key: str = ""
    target: str = ""
    scope: ActionScope = field(
        default_factory=lambda: ActionScope("passive_lookup", "")
    )
    authorization_state: str = REQUIRED
    timeout_seconds: float = 120.0
    output_limit_bytes: int = 12000
    case_id: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported action schema_version")
        try:
            action_id = (
                self.action_id
                if isinstance(self.action_id, uuid.UUID)
                else uuid.UUID(str(self.action_id))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("action_id must be a UUID") from exc
        object.__setattr__(self, "action_id", action_id)
        if self.authorization_state not in _AUTHORIZATION_STATES:
            raise ValueError("invalid authorization_state")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.output_limit_bytes <= 0:
            raise ValueError("output_limit_bytes must be positive")

    @classmethod
    def create(
        cls,
        adapter_key: str,
        target: str,
        *,
        scope: ActionScope | None = None,
        authorization_state: str = REQUIRED,
        timeout_seconds: float = 120.0,
        output_limit_bytes: int = 12000,
        case_id: str | None = None,
    ) -> "ActionRequest":
        return cls(
            schema_version=1,
            action_id=uuid.uuid4(),
            adapter_key=adapter_key,
            target=target,
            scope=scope or ActionScope("passive_lookup", target),
            authorization_state=authorization_state,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            case_id=case_id,
        )


@dataclass(frozen=True, slots=True)
class ActionResult:
    """Immutable outcome. It never performs case/evidence writes."""

    action_id: uuid.UUID
    adapter_key: str
    tool: str
    resolved_executable: str | None
    start_time_utc: str | None
    end_time_utc: str
    exit_code: int | None
    state: str
    termination_reason: str | None
    stdout_preview: str
    stderr_preview: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_byte_count: int
    stderr_byte_count: int
    stdout_truncated: bool
    stderr_truncated: bool
    parsed_result: object | None
    error_class: str | None

    def __post_init__(self) -> None:
        if self.state not in _ACTION_STATES:
            raise ValueError(f"invalid action result state: {self.state}")
        try:
            action_id = (
                self.action_id
                if isinstance(self.action_id, uuid.UUID)
                else uuid.UUID(str(self.action_id))
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("action_id must be a UUID") from exc
        object.__setattr__(self, "action_id", action_id)


class _StreamCapture:
    """Drain one pipe continuously while retaining only a bounded preview."""

    def __init__(self, stream, limit_bytes: int) -> None:
        self.stream = stream
        self.limit_bytes = limit_bytes
        self.hasher = hashlib.sha256()
        self.total_bytes = 0
        self.preview = bytearray()
        self.truncated = False
        self.error: OSError | ValueError | None = None
        self.thread = threading.Thread(
            target=self._drain,
            name="traceos-action-drain",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    return
                self.hasher.update(chunk)
                self.total_bytes += len(chunk)
                remaining = self.limit_bytes - len(self.preview)
                if remaining > 0:
                    self.preview.extend(chunk[:remaining])
                if self.total_bytes > self.limit_bytes:
                    self.truncated = True
        except (OSError, ValueError) as exc:
            self.error = exc

    def join(self, timeout: float) -> None:
        self.thread.join(timeout)

    def close(self) -> None:
        try:
            self.stream.close()
        except OSError:
            pass

    def text(self) -> str:
        return bytes(self.preview).decode("utf-8", "replace")


def _now_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _result(
    request: ActionRequest,
    *,
    adapter_key: str,
    tool: str,
    resolved_executable: str | None,
    start_time_utc: str | None,
    end_time_utc: str,
    exit_code: int | None,
    state: str,
    termination_reason: str | None = None,
    stdout_preview: str = "",
    stderr_preview: str = "",
    stdout_sha256: str = _EMPTY_SHA256,
    stderr_sha256: str = _EMPTY_SHA256,
    stdout_byte_count: int = 0,
    stderr_byte_count: int = 0,
    stdout_truncated: bool = False,
    stderr_truncated: bool = False,
    parsed_result: object | None = None,
    error_class: str | None = None,
) -> ActionResult:
    return ActionResult(
        action_id=request.action_id,
        adapter_key=adapter_key,
        tool=tool,
        resolved_executable=resolved_executable,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        exit_code=exit_code,
        state=state,
        termination_reason=termination_reason,
        stdout_preview=stdout_preview,
        stderr_preview=stderr_preview,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        stdout_byte_count=stdout_byte_count,
        stderr_byte_count=stderr_byte_count,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        parsed_result=parsed_result,
        error_class=error_class,
    )


def _controlled_environment() -> dict[str, str]:
    """Pass only execution variables needed by bundled command-line tools."""

    return {
        "PATH": os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ),
        "LANG": "C",
        "LC_ALL": "C",
    }


def _terminate_process_group(
    proc: subprocess.Popen[bytes],
    grace_seconds: float,
) -> None:
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + grace_seconds
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)

    if proc.poll() is None and pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        proc.wait(timeout=max(0.1, grace_seconds))
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        finally:
            proc.wait()


class ActionRunner:
    """Synchronous runner intended to be called from a worker, not Tk."""

    def __init__(
        self,
        grace_seconds: float = 0.75,
        poll_interval: float = 0.02,
    ) -> None:
        if grace_seconds <= 0 or poll_interval <= 0:
            raise ValueError("grace_seconds and poll_interval must be positive")
        self.grace_seconds = grace_seconds
        self.poll_interval = poll_interval

    def execute(
        self,
        request: ActionRequest,
        cancel_event: threading.Event | None = None,
    ) -> ActionResult:
        """Execute one validated adapter action or return a preflight result."""

        from investigation import get_adapter

        preflight_end = _now_utc()
        try:
            adapter = get_adapter(request.adapter_key)
        except KeyError:
            return _result(
                request,
                adapter_key=request.adapter_key,
                tool=request.adapter_key,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="unknown_adapter",
                error_class="invalid_adapter",
            )

        if cancel_event is not None and cancel_event.is_set():
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=CANCELLED,
                termination_reason="cancelled_before_start",
                error_class="cancelled",
            )

        if adapter.network and request.authorization_state != CONFIRMED:
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="authorization_required",
                error_class="authorization_required",
            )

        try:
            normalized_target = adapter.validate_target(request.target)
        except ValueError:
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="invalid_target",
                error_class="invalid_target",
            )

        if request.scope.mode != "passive_lookup":
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="scope_mismatch",
                error_class="scope_mismatch",
            )

        try:
            normalized_scope_target = adapter.validate_target(request.scope.target)
        except ValueError:
            normalized_scope_target = None

        if (
            normalized_scope_target != normalized_target
            or request.scope.resolver is not None
        ):
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="scope_mismatch",
                error_class="scope_mismatch",
            )

        try:
            argv = adapter.build_argv(normalized_target)
        except ValueError:
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=INVALID_INPUT,
                termination_reason="invalid_target",
                error_class="invalid_target",
            )

        resolved_executable = shutil.which(argv[0])
        if not resolved_executable:
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=None,
                start_time_utc=None,
                end_time_utc=preflight_end,
                exit_code=None,
                state=UNAVAILABLE,
                termination_reason="executable_not_found",
                error_class="unavailable",
            )

        start_time = _now_utc()
        try:
            proc = subprocess.Popen(
                [resolved_executable, *argv[1:]],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                start_new_session=True,
                env=_controlled_environment(),
            )
        except OSError:
            return _result(
                request,
                adapter_key=adapter.key,
                tool=adapter.command,
                resolved_executable=resolved_executable,
                start_time_utc=start_time,
                end_time_utc=_now_utc(),
                exit_code=None,
                state=UNAVAILABLE,
                termination_reason="spawn_failed",
                error_class="unavailable",
            )

        assert proc.stdout is not None
        assert proc.stderr is not None
        stdout = _StreamCapture(proc.stdout, request.output_limit_bytes)
        stderr = _StreamCapture(proc.stderr, request.output_limit_bytes)
        stdout.start()
        stderr.start()

        deadline = time.monotonic() + request.timeout_seconds
        termination: str | None = None
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                termination = "cancel"
                _terminate_process_group(proc, self.grace_seconds)
                break
            if time.monotonic() >= deadline:
                termination = "timeout"
                _terminate_process_group(proc, self.grace_seconds)
                break
            time.sleep(self.poll_interval)

        exit_code = proc.poll()
        if exit_code is None:
            exit_code = proc.wait()

        stdout.join(self.grace_seconds + 1.0)
        stderr.join(self.grace_seconds + 1.0)
        if stdout.thread.is_alive():
            stdout.close()
            stdout.join(0.5)
        if stderr.thread.is_alive():
            stderr.close()
            stderr.join(0.5)
        stdout.close()
        stderr.close()

        stdout_text = stdout.text()
        stderr_text = stderr.text()
        state = COMPLETED if exit_code == 0 and termination is None else FAILED
        termination_reason = None
        error_class = None

        if termination == "timeout":
            state = TIMED_OUT
            termination_reason = "timeout"
            error_class = "timeout"
        elif termination == "cancel":
            state = CANCELLED
            termination_reason = "cancelled"
            error_class = "cancelled"
        elif exit_code != 0:
            termination_reason = "nonzero_exit"
            error_class = "tool_error"

        parsed_result = None
        if state == COMPLETED:
            try:
                parsed_result = adapter.parse_result(
                    stdout_text,
                    stderr_text,
                    exit_code,
                )
            except (TypeError, ValueError):
                state = PARSE_FAILED
                termination_reason = "parser_failure"
                error_class = "parser_failure"

        return _result(
            request,
            adapter_key=adapter.key,
            tool=adapter.command,
            resolved_executable=resolved_executable,
            start_time_utc=start_time,
            end_time_utc=_now_utc(),
            exit_code=exit_code,
            state=state,
            termination_reason=termination_reason,
            stdout_preview=stdout_text,
            stderr_preview=stderr_text,
            stdout_sha256=stdout.hasher.hexdigest(),
            stderr_sha256=stderr.hasher.hexdigest(),
            stdout_byte_count=stdout.total_bytes,
            stderr_byte_count=stderr.total_bytes,
            stdout_truncated=stdout.truncated,
            stderr_truncated=stderr.truncated,
            parsed_result=parsed_result,
            error_class=error_class,
        )


def execute_action(
    request: ActionRequest,
    cancel_event: threading.Event | None = None,
) -> ActionResult:
    """Convenience entry point for one action."""

    return ActionRunner().execute(request, cancel_event)
