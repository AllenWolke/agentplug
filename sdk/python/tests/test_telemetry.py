"""Telemetry fail-safe tests: an empty endpoint must yield the no-op tracer
and never fail startup; an insecure HTTP endpoint builds a provider without
touching the network.

telemetry 失败安全测试：空端点必须返回 no-op tracer 且绝不让启动失败；
不安全的 HTTP 端点在不触网的前提下构建 provider。
"""

from __future__ import annotations

from agent_platform_sdk import NoopTracer
from agent_platform_sdk.telemetry import setup


def test_setup_without_endpoint_fails_safe() -> None:
    tracer, shutdown = setup("generated-agent", "")
    assert isinstance(tracer, NoopTracer)
    with tracer.start_span("any"):
        pass  # must not raise / 不得抛错
    assert shutdown() is None


def test_setup_with_insecure_http_endpoint_builds_provider() -> None:
    tracer, shutdown = setup("generated-agent", "http://127.0.0.1:4318/v1/traces")
    assert not isinstance(tracer, NoopTracer)
    with tracer.start_span("probe"):
        pass
    shutdown()
