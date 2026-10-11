"""Execution stop and isolation regressions. / 执行停止及隔离回归。"""

import asyncio
import base64
import json
from pathlib import Path

import pytest

from agent_platform_sdk.errors import DomainExecutionError, classify_execution_error
from agent_platform_sdk.models import ExecuteRequest
from agent_platform_sdk.task_registry import ExecutionTaskRegistry


def request():
    path = (
        Path(__file__).resolve().parents[3]
        / "contracts/fixtures/execution-v2-request.json"
    )
    envelope = json.loads(path.read_text(encoding="utf-8"))
    claims = (
        base64.urlsafe_b64encode(
            json.dumps({"execution_revision": 2, "lease_token_hash": "a" * 64}).encode()
        )
        .decode()
        .rstrip("=")
    )
    envelope["context_token"] = "fixture." + claims + ".fixture-signature"
    return ExecuteRequest.model_validate(envelope)


@pytest.mark.asyncio
async def test_supervisor_accepts_future_and_releases_registration():
    registry = ExecutionTaskRegistry()
    future = asyncio.get_running_loop().create_future()
    future.set_result("completed")
    assert await registry.execute(request(), lambda: future) == "completed"
    # Same valid execution key can be used after its task has really stopped.
    # 任务真正退出后释放登记，同一有效执行键不会残留为活动任务。
    assert await registry.execute(request(), lambda: future) == "completed"


@pytest.mark.asyncio
async def test_synchronous_action_factory_error_releases_registration():
    registry = ExecutionTaskRegistry()

    def fail():
        raise ValueError("domain failure")

    for _ in range(2):
        with pytest.raises(ValueError, match="domain failure"):
            await registry.execute(request(), fail)


@pytest.mark.asyncio
async def test_cancel_waits_for_cleanup_and_prevents_next_side_effect():
    registry = ExecutionTaskRegistry()
    started, stopped = asyncio.Event(), asyncio.Event()
    effects = []

    async def graph():
        started.set()
        try:
            await asyncio.Event().wait()
            effects.append("model-call")
        finally:
            await asyncio.sleep(0)
            stopped.set()

    execution = asyncio.create_task(registry.execute(request(), graph))
    await started.wait()
    assert await registry.cancel(request())
    assert stopped.is_set() and effects == []
    with pytest.raises(DomainExecutionError, match="EXECUTION_CANCELLED"):
        await execution
    assert not await registry.cancel(request())


@pytest.mark.asyncio
async def test_foreign_principal_cannot_cancel_and_duplicate_does_not_start():
    registry = ExecutionTaskRegistry()
    started = asyncio.Event()

    async def graph():
        started.set()
        await asyncio.Event().wait()

    execution = asyncio.create_task(registry.execute(request(), graph))
    await started.wait()
    foreign = request()
    foreign.scope.principal_id = "another-user"
    assert not await registry.cancel(foreign)
    assert not execution.done()
    with pytest.raises(DomainExecutionError, match="EXECUTION_ALREADY_ACTIVE"):
        await registry.execute(request(), graph)
    await registry.cancel(request())
    with pytest.raises(DomainExecutionError):
        await execution


@pytest.mark.asyncio
async def test_suppressed_cancellation_is_not_acknowledged_as_stopped():
    registry = ExecutionTaskRegistry()
    started, release = asyncio.Event(), asyncio.Event()

    async def graph():
        started.set()
        try:
            await release.wait()
        except asyncio.CancelledError:
            await release.wait()
        return "stopped"

    execution = asyncio.create_task(registry.execute(request(), graph))
    await started.wait()
    try:
        with pytest.raises(DomainExecutionError) as caught:
            await registry.cancel(request(), timeout=0.01)
        status, error = classify_execution_error(caught.value)
        assert status == 409 and error.code == "CANCELLATION_NOT_CONFIRMED"
        assert error.retryable and not execution.done()
    finally:
        release.set()
        assert await execution == "stopped"


@pytest.mark.asyncio
async def test_actual_fastapi_cancel_route_stops_invoke_before_business_ack():
    import httpx

    from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app

    started, stopped = asyncio.Event(), asyncio.Event()
    acknowledgements = []

    async def authorize(envelope, authorization):
        # Transport test only; signature tampering is covered by security tests.
        # 本用例验证真实路由监督，签名篡改另由安全测试覆盖。
        if authorization != "Bearer test-auth":
            raise PermissionError

    async def graph(envelope):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    async def cancelled(run_id, envelope):
        assert stopped.is_set()
        acknowledgements.append(run_id)
        return {}

    app = create_fastapi_agent_app(
        title="test",
        agent_id="test",
        version="1",
        capabilities=["invoke", "cancel"],
        authorize=authorize,
        invoke=graph,
        cancel=cancelled,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        payload = request().model_dump(mode="json")
        payload["operation"] = "invoke"
        invocation = asyncio.create_task(
            client.post(
                "/internal/agent-execution/v2/invoke",
                json=payload,
                headers={"Authorization": "Bearer test-auth"},
            )
        )
        await started.wait()
        payload["operation"] = "cancel"
        denied = await client.post(
            "/internal/agent-execution/v2/runs/run-a/cancel", json=payload
        )
        assert denied.status_code == 401 and not stopped.is_set()
        response = await client.post(
            "/internal/agent-execution/v2/runs/run-a/cancel",
            json=payload,
            headers={"Authorization": "Bearer test-auth"},
        )
        assert response.status_code == 200 and response.json()["status"] == "cancelled"
        failure = await invocation
        assert failure.status_code == 409
        assert failure.json()["code"] == "EXECUTION_CANCELLED"
        assert acknowledgements == ["run-a"]


@pytest.mark.asyncio
async def test_cancel_before_registration_blocks_late_execution_but_not_new_generation():
    registry = ExecutionTaskRegistry()
    effects = []

    async def graph():
        effects.append("executed")
        return "ok"

    old = request()
    assert not await registry.cancel(old)
    with pytest.raises(DomainExecutionError, match="EXECUTION_CANCELLED"):
        await registry.execute(old, graph)
    newer = request()
    claims = (
        base64.urlsafe_b64encode(
            json.dumps({"execution_revision": 3, "lease_token_hash": "b" * 64}).encode()
        )
        .decode()
        .rstrip("=")
    )
    newer.context_token = "fixture." + claims + ".fixture-signature"
    assert await registry.execute(newer, graph) == "ok"
    assert effects == ["executed"]


@pytest.mark.asyncio
async def test_disconnect_supervision_stops_task_before_next_side_effect():
    registry = ExecutionTaskRegistry()
    started, disconnected, stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()
    effects = []

    async def graph():
        started.set()
        try:
            await asyncio.Event().wait()
            effects.append("tool-call")
        finally:
            stopped.set()

    async def connection_lost():
        return disconnected.is_set()

    execution = asyncio.create_task(registry.execute(request(), graph, connection_lost))
    await started.wait()
    disconnected.set()
    with pytest.raises(DomainExecutionError, match="EXECUTION_CANCELLED"):
        await asyncio.wait_for(execution, 1)
    assert stopped.is_set() and effects == []


@pytest.mark.asyncio
async def test_real_fastapi_route_observes_asgi_disconnect():
    from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app

    started, stopped = asyncio.Event(), asyncio.Event()
    incoming = asyncio.Queue()
    outgoing = []

    async def authorize(envelope, authorization):
        assert authorization == "Bearer test"

    async def graph(envelope):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    app = create_fastapi_agent_app(
        title="disconnect",
        agent_id="test",
        version="1",
        capabilities=["invoke"],
        authorize=authorize,
        invoke=graph,
    )
    payload = request().model_dump(mode="json")
    payload["operation"] = "invoke"
    await incoming.put(
        {
            "type": "http.request",
            "body": json.dumps(payload).encode(),
            "more_body": False,
        }
    )

    async def send(message):
        outgoing.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/internal/agent-execution/v2/invoke",
        "raw_path": b"/internal/agent-execution/v2/invoke",
        "query_string": b"",
        "headers": [
            (b"content-type", b"application/json"),
            (b"authorization", b"Bearer test"),
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("test", 80),
    }
    execution = asyncio.create_task(app(scope, incoming.get, send))
    await asyncio.wait_for(started.wait(), 1)
    await incoming.put({"type": "http.disconnect"})
    await asyncio.wait_for(execution, 1)
    assert stopped.is_set()
    assert outgoing[0]["status"] == 409
    assert b"EXECUTION_CANCELLED" in outgoing[1]["body"]
