"""FastAPI adapter for async Agent hooks.

FastAPI remains an optional transport dependency of the Agent image. The
platform SDK owns all standard execution routes; business modules provide only
typed hooks and a lifecycle context.
FastAPI 仅是 Agent 镜像的可选传输依赖；平台 SDK 统一持有执行路由，业务模块只
提供 Hook 和生命周期上下文。
"""

import re
import inspect
import httpx
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from .models import EventRequest, ExecuteRequest, ExecuteResponse, validate_event_cursor
from .errors import DomainExecutionError, classify_execution_error
from .capability_client import GatewayError
from .task_registry import ExecutionTaskRegistry

AuthHook = Callable[[ExecuteRequest | EventRequest, str], Any]
InvokeHook = Callable[[ExecuteRequest], Awaitable[dict[str, Any] | ExecuteResponse]]
RunHook = InvokeHook
# The optional third flag is injected only by the trusted platform dispatcher
# after the original capability body has been verified.
# 第三个参数仅由受信平台 Dispatcher 在完成原始能力正文校验后注入。
ActionHook = Callable[..., Awaitable[dict[str, Any] | ExecuteResponse]]
EventsHook = Callable[[str, EventRequest, str], Awaitable[Any]]
ReadyHook = Callable[[], Awaitable[bool]]


def _validate_manifest_schema(agent_id: str, name: str, value: Any) -> str:
    """Require a canonical, agent-bound input/output schema URI."""
    if (
        name not in {"input", "output"}
        or not isinstance(agent_id, str)
        or not agent_id
    ):
        raise ValueError("invalid manifest schema identity")
    if not isinstance(value, str) or re.fullmatch(
        rf"schema://{re.escape(agent_id)}/{name}/v[1-9][0-9]*", value
    ) is None:
        raise ValueError(
            f"manifest {name} schema must be bound to this agent and use a canonical positive version"
        )
    return value


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def create_fastapi_agent_app(
    *,
    title: str,
    agent_id: str,
    version: str,
    capabilities: list[str],
    authorize: AuthHook,
    invoke: InvokeHook | None = None,
    run: RunHook | None = None,
    resume: ActionHook | None = None,
    replay_runtime_recovery: ActionHook | None = None,
    cancel: ActionHook | None = None,
    events: EventsHook | None = None,
    readiness: ReadyHook | None = None,
    lifespan: Callable[[Any], AbstractAsyncContextManager[Any]] | None = None,
    manifest_extra: dict[str, Any] | None = None,
    task_registry: ExecutionTaskRegistry | None = None,
    background_run: bool = False,
    finalize_response: Callable[[ExecuteRequest, ExecuteResponse], ExecuteResponse] | None = None,
) -> Any:
    """Build a FastAPI app with the complete Agent Execution v2 surface."""

    from fastapi import FastAPI, Header, HTTPException, Request

    if background_run and (run is None or cancel is None):
        raise ValueError("background run requires run and cancel hooks")

    @asynccontextmanager
    async def managed(app: Any):
        if lifespan is None:
            try:
                yield
            finally:
                await registry.shutdown()
            return
        async with lifespan(app):
            try:
                yield
            finally:
                await registry.shutdown()

    app = FastAPI(title=title, version=version, lifespan=managed)
    from .telemetry import TraceContextMiddleware

    app.add_middleware(TraceContextMiddleware)
    # A lifecycle adapter may share supervision with background run hooks.
    # Cancellation must observe the same registry that owns the actual task.
    registry = task_registry if task_registry is not None else ExecutionTaskRegistry()

    def supervised_response(request: ExecuteRequest, result: ExecuteResponse) -> ExecuteResponse:
        # Business-supplied response fields are not execution exit evidence.
        result = result.model_copy(update={"handoff": None, "agent_group_handoff": None})
        return finalize_response(request, result) if finalize_response is not None else result

    async def execution_exception_handler(_request: Any, exc: Exception) -> Any:
        from fastapi.responses import JSONResponse

        status, error = classify_execution_error(exc)
        return JSONResponse(error.model_dump(exclude_none=True), status_code=status)

    for exception_type in (
        DomainExecutionError,
        GatewayError,
        ValueError,
        PermissionError,
        TimeoutError,
        httpx.TransportError,
        Exception,
    ):
        app.add_exception_handler(exception_type, execution_exception_handler)
    manifest: dict[str, Any] = {
        "manifest_version": "agent-manifest/v1",
        "agent_id": agent_id,
        "version": version,
        "capabilities": capabilities,
        "execution_protocols": ["agent-execution/v2", "grpc-agent-execution/v2"],
        "schemas": {
            "input": f"schema://{agent_id}/input/v1",
            "output": f"schema://{agent_id}/output/v1",
            "event": "schema://agent-platform/event/v1",
            "checkpoint": "schema://agent-platform/checkpoint/v1",
        },
        "runtime": {
            "transport": "http",
            "isolation": "container",
            "health_path": "/health/ready",
        },
    }
    if manifest_extra is not None:
        if not isinstance(manifest_extra, dict):
            raise ValueError("manifest_extra must be an object")
        if "schemas" in manifest_extra:
            extra_schemas = manifest_extra["schemas"]
            if not isinstance(extra_schemas, dict):
                raise ValueError("manifest schemas must be an object")
            manifest["schemas"].update(extra_schemas)
        manifest.update(
            {key: value for key, value in manifest_extra.items() if key != "schemas"}
        )
    for schema_name in ("input", "output"):
        manifest["schemas"][schema_name] = _validate_manifest_schema(
            agent_id, schema_name, manifest["schemas"].get(schema_name)
        )

    async def check(request: ExecuteRequest, authorization: str) -> None:
        try:
            await _maybe_await(authorize(request, authorization))
        except HTTPException:
            raise
        except PermissionError as exc:
            raise HTTPException(401, "invalid execution context") from exc

    @app.get("/.well-known/agent-manifest.json")
    async def agent_manifest() -> dict[str, Any]:
        return manifest

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live", "service": agent_id}

    @app.get("/health/ready")
    async def ready() -> Any:
        ok = True if readiness is None else await readiness()
        from fastapi.responses import JSONResponse

        return JSONResponse(
            {"status": "ready" if ok else "not_ready"}, status_code=200 if ok else 503
        )

    @app.post("/internal/agent-execution/v2/invoke", response_model=ExecuteResponse,
              response_model_exclude_none=True)
    async def invoke_route(
        request: ExecuteRequest,
        http_request: Request,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> ExecuteResponse:
        if invoke is None:
            raise HTTPException(404, "invoke is not supported")
        await check(request, authorization)
        # The platform signs a fresh authorized command before dispatch. Its
        # synchronous invocation seam accepts only the signed run/invoke action.
        # 平台投递前重新签发已授权命令；同步入口只接受签名绑定的 run/invoke。
        if request.operation not in {"invoke", "run"}:
            raise HTTPException(422, "operation must be invoke or run")
        result = await registry.execute(
            request, lambda: invoke(request), http_request.is_disconnected
        )
        if isinstance(result, ExecuteResponse):
            return supervised_response(request, result)
        return ExecuteResponse(
            run_id=request.scope.run_id, status="succeeded", output=result
        )

    @app.post(
        "/internal/agent-execution/v2/runs",
        response_model=ExecuteResponse,
        status_code=202,
        response_model_exclude_none=True,
    )
    async def run_route(
        request: ExecuteRequest,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> ExecuteResponse:
        if run is None:
            raise HTTPException(404, "run is not supported")
        await check(request, authorization)
        if request.operation != "run":
            raise HTTPException(422, "operation must be run")
        if background_run:
            # The hook owns RunStore completion/failure. Supervision persists
            # after HTTP ACK and shares exact-generation cancellation proof.
            await registry.start_background(request, lambda: run(request))
            return ExecuteResponse(run_id=request.scope.run_id, status="accepted")
        result = await run(request)
        if isinstance(result, ExecuteResponse):
            return supervised_response(request, result)
        return ExecuteResponse(
            run_id=request.scope.run_id, status="accepted", output=result
        )

    @app.post(
        "/internal/agent-execution/v2/runs/{run_id}/resume",
        response_model=ExecuteResponse,
        response_model_exclude_none=True,
    )
    async def resume_route(
        run_id: str,
        request: ExecuteRequest,
        http_request: Request,
        authorization: str = Header(default="", alias="Authorization"),
        platform_resume_dispatch: str = Header(
            default="", alias="X-Platform-Resume-Dispatch"
        ),
        platform_resume_input: str = Header(
            default="", alias="X-Platform-Resume-Input"
        ),
    ) -> ExecuteResponse:
        if resume is None:
            raise HTTPException(404, "resume is not supported")
        await check(request, authorization)
        if platform_resume_dispatch or platform_resume_input:
            raise HTTPException(400, "unsigned resume headers are forbidden")
        if request.operation != "resume" or request.resume_input is None:
            raise HTTPException(422, "signed resume operation and input are required")
        if run_id != request.scope.run_id:
            raise HTTPException(409, "run binding mismatch")
        if (request.resume_input.get("version") in {"runtime-recovery/v1", "agent-group-resume/v1"}
                and registry.generation_replay_state(registry.key(request)) in {"active", "exited"}):
            # Same-generation runtime/group replay is a narrow lifecycle-owned
            # read. Never pass it through a business resume hook or register a
            # second task under the original handler's key.
            if replay_runtime_recovery is None:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            result = await replay_runtime_recovery(run_id, request, True, request.resume_input)
            from fastapi.responses import JSONResponse
            if not isinstance(result, ExecuteResponse):
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            result = supervised_response(request, result)
            if result.status == "running":
                return JSONResponse(status_code=202, content=result.model_dump(exclude_none=True))
            if result.status not in {"waiting", "succeeded", "failed", "cancelled"}:
                raise DomainExecutionError("RUN_RESUME_UNCONFIRMED")
            return result
        result = await registry.execute(
            request,
            lambda: resume(run_id, request, True, request.resume_input),
            http_request.is_disconnected,
        )
        if isinstance(result, ExecuteResponse):
            return supervised_response(request, result)
        return ExecuteResponse(run_id=run_id, status="running", output=result)

    @app.post(
        "/internal/agent-execution/v2/runs/{run_id}/cancel",
        response_model=ExecuteResponse,
        response_model_exclude_none=True,
    )
    async def cancel_route(
        run_id: str,
        request: ExecuteRequest,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> ExecuteResponse:
        if cancel is None:
            raise HTTPException(404, "cancel is not supported")
        await check(request, authorization)
        if request.operation != "cancel" or run_id != request.scope.run_id:
            raise HTTPException(409, "run binding mismatch")
        # A signed request must stop the actual graph before acknowledging.
        # 签名取消必须先等待真实业务图停止，再由业务 Hook 确认持久化状态。
        stopped = await registry.cancel(request)
        if not stopped and not registry.has_exit_proof(request):
            raise DomainExecutionError("CANCELLATION_NOT_CONFIRMED")
        result = await cancel(run_id, request)
        if isinstance(result, ExecuteResponse):
            return result.model_copy(update={"handoff": None, "agent_group_handoff": None})
        return ExecuteResponse(run_id=run_id, status="cancelled", output=result)

    @app.post("/internal/agent-execution/v2/runs/{run_id}/events")
    async def events_route(
        run_id: str,
        request: EventRequest,
        authorization: str = Header(default="", alias="Authorization"),
    ) -> Any:
        if events is None:
            raise HTTPException(404, "events are not supported")
        try:
            validate_event_cursor(request.after_seq)
        except (TypeError, ValueError):
            raise HTTPException(422, "invalid event cursor") from None
        await _maybe_await(authorize(request, authorization))
        if run_id != request.scope.run_id:
            raise HTTPException(422, "invalid event cursor")
        return await events(run_id, request, authorization)

    return app
