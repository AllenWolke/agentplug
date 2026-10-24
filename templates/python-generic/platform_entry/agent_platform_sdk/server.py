"""ExecutionServer: the SDK's transport封装 for the full Execution v2 surface.

It mounts invoke plus the optional run/resume/cancel/events lifecycle entries,
verifies every caller through the platform PEP, and keeps the business seam
behind the verified boundary. Generated Agents configure it instead of
re-implementing transport, verification or the run state machine.

ExecutionServer 是 SDK 的传输封装：挂载完整 Execution v2 入口（invoke 与可选
run/resume/cancel/events 生命周期入口），所有调用先经平台 PEP 校验，业务接缝
保持在已验证边界之后。生成 Agent 只做配置，不重复实现传输、校验与状态机。
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from .lifecycle import (
    EVENT_STARTED,
    MEMORY_RUN_STORE_LABEL,
    IdempotencyConflictError,
    InvalidTransitionError,
    RunStore,
    RunUnknownError,
)
from .models import (AppError, EventRequest, ExecuteRequest, ExecuteResponse,
                     normalize_execution_event, validate_event_cursor)
from .security import ContextVerifier, ContextVerificationError, TrustedContext
from .tracing import Attribute, NoopTracer, Tracer

INVOKE_PATH = "/internal/agent-execution/v2/invoke"
RUNS_PATH = "/internal/agent-execution/v2/runs"
_RUN_ENTRY = re.compile(r"^/internal/agent-execution/v2/runs/(?P<run_id>[^/]+)/(?P<action>resume|cancel|events|checkpoint)$")

# RunHandler is the only business seam: verified context in, output out.
# Business code must observe the cancelled event for cooperative cancellation.
# RunHandler 是唯一业务接缝：输入已验证上下文，输出结果；业务必须观察取消
# 事件以支持协作式取消。
RunHandler = Callable[[TrustedContext, Any, threading.Event], dict[str, Any]]
InvokeHandler = Callable[[TrustedContext], dict[str, Any]]


class ServerConfigError(ValueError):
    """Raised when the wiring is incomplete; the process must refuse to start
    rather than serve an unverified surface. / 接线不完整；进程必须拒绝启动。
    """


@dataclass(slots=True)
class ServerConfig:
    public_key: Ed25519PublicKey
    issuer: str
    audience: str
    agent_id: str
    store: RunStore
    capabilities: list[str] = field(default_factory=lambda: ["invoke"])
    agent_version: str = "0.1.0"
    # Optional; None means NoopTracer and no telemetry leaves the process.
    # 可选；None 表示 NoopTracer，不产生任何遥测输出。
    tracer: Tracer | None = None
    # Optional (tests); None means wall clock. / 可选（测试用）；None 表示真实时钟。
    now: Callable[[], int] | None = None
    # Required when the matching capability is advertised. / 声明对应能力时必填。
    invoke: InvokeHandler | None = None
    run: RunHandler | None = None
    # Pure validation follows verification and precedes business admission.
    validate_input: Callable[[TrustedContext], None] | None = None

    def advertised(self) -> dict[str, bool]:
        capability = {name: True for name in self.capabilities}
        if not capability:
            capability = {"invoke": True}
        return capability


class ExecutionServer:
    """Serves the Execution v2 surface for one Agent. / 为单个 Agent 服务 v2 接口。"""

    def __init__(self, config: ServerConfig) -> None:
        if not isinstance(config.public_key, Ed25519PublicKey):
            raise ServerConfigError("platform public key is required")
        if not config.issuer or not config.audience or not config.agent_id:
            raise ServerConfigError("issuer, audience and agent id are required")
        if config.store is None:
            raise ServerConfigError("a run store is required")
        capability = config.advertised()
        if capability.get("invoke") and config.invoke is None:
            raise ServerConfigError("invoke capability requires an invoke handler")
        if capability.get("run"):
            if config.run is None:
                raise ServerConfigError("run capability requires a run handler")
            # The lifecycle entries always travel together with run so a started
            # run can always be observed, resumed and cancelled.
            # 生命周期入口必须与 run 同行：已启动的运行始终可观察、可恢复、可取消。
            for required in ("resume", "cancel", "events"):
                if not capability.get(required):
                    raise ServerConfigError(f"run capability requires {required}")
        self.config = config
        self.capability = capability
        self._now = config.now or (lambda: int(time.time()))
        raw = config.public_key.public_bytes_raw()
        self._verifier = ContextVerifier(raw, config.issuer, config.audience, now=self._now)

    # -- routing ---------------------------------------------------------

    def handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?")[0]
                if path == "/health/ready":
                    self.send_response(200)
                    self.end_headers()
                    return
                if path == "/.well-known/agent-manifest.json":
                    server._write_json(self, 200, server._manifest())
                    return
                self.send_error(404)

            def do_POST(self) -> None:  # noqa: N802
                path = self.path.split("?")[0]
                if path == INVOKE_PATH:
                    server._execute(self, "invoke")
                elif path == RUNS_PATH:
                    server._execute(self, "run")
                else:
                    match = _RUN_ENTRY.match(path)
                    if match is None:
                        self.send_error(404)
                        return
                    action = match.group("action")
                    if action == "events":
                        server._events(self, match.group("run_id"))
                    else:
                        server._execute(self, action, match.group("run_id"))

        return Handler

    def serve(self, address: tuple[str, int]) -> ThreadingHTTPServer:
        httpd = ThreadingHTTPServer(address, self.handler())
        httpd.daemon_threads = True
        return httpd

    def _manifest(self) -> dict[str, Any]:
        return {
            "manifest_version": "agent-manifest/v1",
            "agent_id": self.config.agent_id,
            "version": self.config.agent_version,
            "execution_protocols": ["agent-execution/v2"],
            "capabilities": sorted(self.capability),
            "schemas": {
                "input": f"schema://{self.config.agent_id}/input/v1",
                "output": f"schema://{self.config.agent_id}/output/v1",
            },
            "runtime": {
                "transport": "http",
                "isolation": "container",
                "run_store": self._store_label(),
            },
        }

    def _store_label(self) -> str:
        from .lifecycle import MemoryRunStore

        return MEMORY_RUN_STORE_LABEL if isinstance(self.config.store, MemoryRunStore) else "durable"

    # -- execution entries -------------------------------------------------

    def _execute(self, handler: BaseHTTPRequestHandler, operation: str, run_id: str | None = None) -> None:
        tracer = self.config.tracer or NoopTracer()
        with tracer.start_span(
            f"agentplatform.{operation}",
            Attribute(key="agentplatform.operation", value=operation),
        ):
            if handler.command != "POST":
                self._write_error(handler, 405, "METHOD_NOT_ALLOWED", "operation requires POST")
                return
            if not self.capability.get(operation):
                self._write_error(handler, 404, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent")
                return
            request = self._decode_execute(handler)
            if request is None:
                return
            if request.operation != operation:
                self._write_error(handler, 400, "REQUEST_INVALID", "unexpected operation for this entry")
                return
            if not self._bound_bearer(handler, request.context_token):
                self._write_error(handler, 401, "CAPABILITY_INVALID", "execution capability is invalid")
                return
            try:
                trusted = self._verifier.verify(request.context_token, request)
            except ContextVerificationError:
                # The failure reason is never echoed back; it may reveal tenant
                # or claim details. / 不回显失败原因，避免泄漏租户或声明细节。
                self._write_error(handler, 401, "CAPABILITY_INVALID", "execution capability is invalid")
                return
            if operation in {"invoke", "run"} and self.config.validate_input is not None:
                try:
                    self.config.validate_input(trusted)
                except ValueError:
                    self._write_json(handler, 422, self._envelope(
                        request.scope.run_id, status="failed", error=AppError(
                            code="INVALID_REQUEST", message="business input is invalid", retryable=False)))
                    return
                except Exception:
                    self._write_error(handler, 500, "INPUT_VALIDATOR_FAILED", "input validation unavailable")
                    return
            if operation == "invoke":
                self._handle_invoke(handler, trusted)
            elif operation == "run":
                self._handle_run(handler, request)
            elif operation == "resume":
                self._handle_resume(handler, trusted, run_id or "")
            else:
                self._handle_cancel(handler, trusted, run_id or "")

    def _handle_invoke(self, handler: BaseHTTPRequestHandler, trusted: TrustedContext) -> None:
        try:
            output = (self.config.invoke or (lambda _t: {}))(trusted)
        except Exception:
            self._write_json(handler, 500, self._envelope(trusted.request.scope.run_id, error=AppError(
                code="INTERNAL", message="the agent failed to process the request", retryable=True)))
            return
        self._write_json(handler, 200, self._envelope(trusted.request.scope.run_id, status="succeeded", output=output))

    def _handle_run(self, handler: BaseHTTPRequestHandler, request: ExecuteRequest) -> None:
        try:
            _, created = self.config.store.start_run(request)
        except (IdempotencyConflictError, RunUnknownError, InvalidTransitionError) as exc:
            self._write_app_failure(handler, request.scope.run_id, exc)
            return
        if created:
            threading.Thread(target=self._execute_run, args=(request,), daemon=True).start()
        self._write_json(handler, 202, self._envelope(request.scope.run_id, status="running"))

    def _execute_run(self, request: ExecuteRequest) -> None:
        run_id = request.scope.run_id
        tracer = self.config.tracer or NoopTracer()
        with tracer.start_span(
            "agentplatform.run.execute",
            Attribute(key="agentplatform.run_id", value=run_id),
        ):
            cancelled = self.config.store.cancelled(run_id)
            try:
                self.config.store.append_event(run_id, EVENT_STARTED, {})
            except (RunUnknownError, InvalidTransitionError):
                return
            trusted = TrustedContext(claims={}, request=request)
            sink = _StoreSink(store=self.config.store, run_id=run_id)
            try:
                output = (self.config.run or (lambda *_a: {}))(trusted, sink, cancelled)
            except Exception:
                try:
                    self.config.store.fail(run_id, AppError(
                        code="INTERNAL", message="the agent failed to process the request", retryable=True))
                except (RunUnknownError, InvalidTransitionError):
                    pass
                return
            try:
                self.config.store.complete(run_id, output)
            except (RunUnknownError, InvalidTransitionError):
                pass

    def _handle_resume(self, handler: BaseHTTPRequestHandler, trusted: TrustedContext, run_id: str) -> None:
        if run_id != trusted.request.scope.run_id:
            self._write_error(handler, 400, "REQUEST_INVALID", "path run id must match the verified scope")
            return
        if trusted.request.resume_input is None:
            self._write_error(handler, 400, "REQUEST_INVALID", "signed resume_input is required")
            return
        try:
            self.config.store.resume(run_id, trusted.request.resume_input)
            status = "running"
            record = self.config.store.get_run(run_id)
            if record is not None:
                status = record.status
        except (IdempotencyConflictError, RunUnknownError, InvalidTransitionError) as exc:
            self._write_app_failure(handler, run_id, exc)
            return
        self._write_json(handler, 202, self._envelope(run_id, status=status))

    def _handle_cancel(self, handler: BaseHTTPRequestHandler, trusted: TrustedContext, run_id: str) -> None:
        if run_id != trusted.request.scope.run_id:
            self._write_error(handler, 400, "REQUEST_INVALID", "path run id must match the verified scope")
            return
        reason = ""
        value = trusted.request.input.get("reason")
        if isinstance(value, str):
            reason = value
        try:
            record = self.config.store.cancel(run_id, reason)
        except (IdempotencyConflictError, RunUnknownError, InvalidTransitionError) as exc:
            self._write_app_failure(handler, run_id, exc)
            return
        self._write_json(handler, 202, self._envelope(run_id, status=record.status, output=record.output))

    # -- events -------------------------------------------------------------

    def _events(self, handler: BaseHTTPRequestHandler, run_id: str) -> None:
        tracer = self.config.tracer or NoopTracer()
        with tracer.start_span(
            "agentplatform.events",
            Attribute(key="agentplatform.operation", value="events"),
        ):
            if handler.command != "POST":
                self._write_error(handler, 405, "METHOD_NOT_ALLOWED", "operation requires POST")
                return
            if not self.capability.get("events"):
                self._write_error(handler, 404, "UNSUPPORTED_CAPABILITY", "capability is not advertised by this agent")
                return
            request = self._decode_event(handler)
            if request is None:
                return
            try:
                validate_event_cursor(request.after_seq)
            except (TypeError, ValueError):
                self._write_error(handler, 400, "REQUEST_INVALID", "event cursor is invalid")
                return
            if not self._bound_bearer(handler, request.context_token):
                self._write_error(handler, 401, "CAPABILITY_INVALID", "execution capability is invalid")
                return
            try:
                self._verifier.verify_event(request.context_token, request)
            except ContextVerificationError:
                self._write_error(handler, 401, "CAPABILITY_INVALID", "execution capability is invalid")
                return
            if run_id != request.scope.run_id:
                self._write_error(handler, 400, "REQUEST_INVALID", "path run id must match the verified scope")
                return
            try:
                raw_events = self.config.store.events_after(run_id, request.after_seq)
            except (RunUnknownError, InvalidTransitionError) as exc:
                self._write_app_failure(handler, run_id, exc)
                return
            try:
                events = []
                cursor = request.after_seq
                for raw_event in raw_events:
                    event = normalize_execution_event(raw_event)
                    if event.run_id != run_id or event.seq <= cursor:
                        raise ValueError("invalid event order")
                    events.append(event)
                    cursor = event.seq
            except (TypeError, ValueError):
                self._write_app_failure(handler, run_id, InvalidTransitionError("invalid event sequence"))
                return
            # A bounded replay that closes the stream afterwards; this is not
            # an unbounded live tail. / 有界重放后关闭流；不是无限实时流。
            body = "".join(
                f"id: {event.seq}\nevent: {event.event_type}\ndata: {event.model_dump_json()}\n\n"
                for event in events
            )
            raw = body.encode("utf-8")
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Cache-Control", "no-cache")
            handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)

    # -- helpers --------------------------------------------------------

    def _decode_execute(self, handler: BaseHTTPRequestHandler) -> ExecuteRequest | None:
        payload = self._read_json(handler)
        if payload is None:
            return None
        try:
            request = ExecuteRequest.model_validate(payload)
        except ValidationError:
            self._write_error(handler, 400, "REQUEST_INVALID", "request must be one valid JSON object")
            return None
        if request.protocol_version != "agent-execution/v2":
            self._write_error(handler, 400, "REQUEST_INVALID", "unexpected protocol version")
            return None
        return request

    def _decode_event(self, handler: BaseHTTPRequestHandler) -> EventRequest | None:
        payload = self._read_json(handler)
        if payload is None:
            return None
        try:
            request = EventRequest.model_validate(payload)
        except ValidationError:
            self._write_error(handler, 400, "REQUEST_INVALID", "request must be one valid JSON object")
            return None
        if request.protocol_version != "agent-execution/v2":
            self._write_error(handler, 400, "REQUEST_INVALID", "unexpected protocol version")
            return None
        return request

    def _read_json(self, handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
        try:
            length = int(handler.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_048_576:
                raise ValueError("body limit")
            payload = json.loads(handler.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("object required")
            return payload
        except (ValueError, json.JSONDecodeError):
            self._write_error(handler, 400, "REQUEST_INVALID", "request must be one valid JSON object")
            return None

    def _bound_bearer(self, handler: BaseHTTPRequestHandler, token: str) -> bool:
        # Bind the envelope token to the request credential so a stolen header
        # cannot be paired with a different body.
        # 将信封令牌与请求凭证绑定，窃取的头部无法与别的正文配对。
        return bool(token) and handler.headers.get("Authorization") == "Bearer " + token

    def _envelope(self, run_id: str, *, status: str = "succeeded", output: dict[str, Any] | None = None, error: AppError | None = None) -> ExecuteResponse:
        return ExecuteResponse(run_id=run_id, status=status, output=output or {}, error=error)  # type: ignore[arg-type]

    def _write_app_failure(self, handler: BaseHTTPRequestHandler, run_id: str, exc: Exception) -> None:
        if isinstance(exc, IdempotencyConflictError):
            status, code, message, retryable = 409, "IDEMPOTENCY_CONFLICT", "run id was reused with a different idempotency key", False
        elif isinstance(exc, RunUnknownError):
            status, code, message, retryable = 404, "RUN_UNKNOWN", "run is unknown", False
        elif isinstance(exc, InvalidTransitionError):
            status, code, message, retryable = 500, "INVALID_TRANSITION", "run state transition is invalid", False
        else:
            status, code, message, retryable = 500, "INTERNAL", "the agent failed to process the request", True
        self._write_json(handler, status, self._envelope(run_id, error=AppError(code=code, message=message, retryable=retryable)))

    def _write_error(self, handler: BaseHTTPRequestHandler, status: int, code: str, message: str) -> None:
        self._write_json(handler, status, AppError(code=code, message=message, retryable=False).model_dump())

    def _write_json(self, handler: BaseHTTPRequestHandler, status: int, value: Any) -> None:
        if isinstance(value, ExecuteResponse):
            value = value.model_dump(exclude_none=True, mode="json")
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)


class _StoreSink:
    """Adapts the RunStore into the EventSink seen by business handlers.

    将 RunStore 适配为业务处理器看到的 EventSink。
    """

    def __init__(self, store: RunStore, run_id: str) -> None:
        self._store = store
        self._run_id = run_id

    def append(self, event_type: str, payload: dict[str, Any]) -> None:
        self._store.append_event(self._run_id, event_type, payload)
