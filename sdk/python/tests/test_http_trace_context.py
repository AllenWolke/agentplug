"""Actual shared FastAPI propagation; 真实共享入口的父子追踪与脱敏回归。"""

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agent_platform_sdk.fastapi_factory import create_fastapi_agent_app


@pytest.mark.asyncio
async def test_fastapi_parent_propagation_and_safe_failed_span(monkeypatch):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer", provider.get_tracer)
    app = create_fastapi_agent_app(
        title="fixture",
        agent_id="fixture",
        version="1",
        capabilities=[],
        authorize=lambda *_: None,
    )

    @app.get("/fixture/error")
    async def error():
        raise RuntimeError("private-fixture-secret")

    observed = []

    @app.get("/fixture/child")
    async def child():
        with trace.get_tracer("fixture.domain").start_as_current_span("business"):
            observed.append(trace.get_current_span().get_span_context().trace_id)
        return {"status": "ok"}

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://fixture",
        ) as client:
            parent = "00-11111111111111111111111111111111-2222222222222222-01"
            response = await client.get(
                "/fixture/child?secret=private-fixture-secret",
                headers={
                    "traceparent": parent,
                    "Authorization": "private-fixture-secret",
                },
            )
            assert response.status_code == 200
            failure = await client.get(
                "/fixture/error", headers={"traceparent": parent}
            )
            assert failure.status_code == 500
        spans = exporter.get_finished_spans()
        http_spans = [span for span in spans if span.name == "agent.http"]
        assert len(http_spans) == 2
        assert all(
            span.parent.span_id == int("2222222222222222", 16) for span in http_spans
        )
        assert observed == [int("11111111111111111111111111111111", 16)]
        business = next(span for span in spans if span.name == "business")
        assert business.parent.span_id == http_spans[0].context.span_id
        assert http_spans[1].status.description == "HTTP_EXECUTION_FAILED"
        for span in spans:
            assert not span.events  # No raw exception events; 不记录原始异常。
            assert "private-fixture-secret" not in str(dict(span.attributes))
            assert "private-fixture-secret" not in (span.status.description or "")
    finally:
        provider.shutdown()
