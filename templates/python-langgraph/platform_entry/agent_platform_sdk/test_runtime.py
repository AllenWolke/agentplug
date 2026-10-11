from __future__ import annotations

import pytest

from agent_platform_sdk import runtime
from agent_platform_sdk.runtime_mode import RuntimeMode


class _Tracer:
    def __init__(self) -> None:
        self.closed = False

    def shutdown(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_start_agent_runtime_owns_shared_lifecycle(monkeypatch) -> None:
    checkpointer = object()
    closed = False

    async def fake_get_checkpointer():
        return checkpointer

    async def fake_close_checkpointer():
        nonlocal closed
        closed = True

    tracer = _Tracer()
    monkeypatch.setattr(runtime, "get_checkpointer", fake_get_checkpointer)
    monkeypatch.setattr(runtime, "close_checkpointer", fake_close_checkpointer)
    monkeypatch.setattr(runtime, "configure_telemetry", lambda _: tracer)
    monkeypatch.setattr(
        runtime,
        "resolve_runtime_mode",
        lambda: RuntimeMode("http://platform", "platform", False),
    )
    monkeypatch.setenv("PLATFORM_RUN_TOKEN", "test-token")

    class _Platform:
        async def ready(self):
            return True

    monkeypatch.setattr(runtime, "PlatformRunClient", lambda *_args, **_kwargs: _Platform())

    captured: dict[str, object] = {}

    def build_graph(actual):
        captured["checkpointer"] = actual
        return {"graph": "business"}

    async def work(payload):
        return payload

    agent = await runtime.start_agent_runtime(
        agent_id="test-agent",
        graph_builder=build_graph,
        verifier_factory=lambda: "verifier",
        work=work,
        grpc_port=0,
        grpc_http_base_url="http://127.0.0.1:1",
        local_concurrency=1,
        enable_grpc_transport=False,
    )

    assert captured["checkpointer"] is checkpointer
    assert agent.graph == {"graph": "business"}
    assert agent.verifier == "verifier"
    assert await agent.run_gateway.ready() is True

    await agent.close()
    assert closed is True
    assert tracer.closed is True


def test_runtime_mode_keeps_platform_execution_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("PLATFORM_RUN_BASE_URL", raising=False)
    monkeypatch.setenv("PLATFORM_RUN_EXECUTOR", "platform")

    with pytest.raises(RuntimeError, match="PLATFORM_RUN_BASE_URL"):
        # The async function validates mode before any external dependency is
        # touched; constructing the coroutine is enough to exercise the
        # boundary only when awaited.
        import asyncio

        asyncio.run(
            runtime.start_agent_runtime(
                agent_id="test-agent",
                graph_builder=lambda _: None,
                verifier_factory=lambda: None,
                work=lambda _: None,
                grpc_port=0,
                grpc_http_base_url="http://127.0.0.1:1",
                local_concurrency=1,
                enable_grpc_transport=False,
            )
        )
