"""OpenTelemetry implementation of the SDK's tracing seam.

Generated Agents call :func:`setup` once at startup and inject the returned
tracer into :class:`~agent_platform_sdk.server.ServerConfig`. An empty
endpoint yields the no-op tracer: absence of a collector must never fail
startup.

telemetry 包提供 SDK 追踪接缝的 OpenTelemetry 实现：生成 Agent 在启动时调用
一次 setup，并把返回的 tracer 注入 ServerConfig；端点为空时返回 no-op tracer
——缺失收集器绝不能导致启动失败。
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .tracing import Attribute, NoopTracer, Span, Tracer


class TraceContextMiddleware:
    """Shared ASGI tracing without exporting URLs, bodies or credentials.

    统一 ASGI 追踪接缝，保留上游父级，不导出 URL、正文、凭据或用户身份。
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            from opentelemetry import trace
            from opentelemetry.trace.propagation.tracecontext import (
                TraceContextTextMapPropagator,
            )
            from opentelemetry.trace import SpanKind, Status, StatusCode
        except ImportError:
            # Optional SDK tracing stays optional without a configured exporter.
            # 未配置导出器时允许核心 SDK 不安装可观测依赖。
            import os

            if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv(
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
            ):
                raise RuntimeError("OpenTelemetry dependencies are not installed")
            await self.app(scope, receive, send)
            return
        carrier = {
            key.decode("ascii").lower(): value.decode("ascii", errors="ignore")
            for key, value in scope.get("headers", [])
            if key.lower() in (b"traceparent", b"tracestate")
        }
        parent = TraceContextTextMapPropagator().extract(carrier)
        tracer = trace.get_tracer("agent_platform_sdk.http")
        with tracer.start_as_current_span(
            "agent.http",
            context=parent,
            kind=SpanKind.SERVER,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            span.set_attribute("http.request.method", scope.get("method", ""))

            async def traced_send(message: Any) -> None:
                if message["type"] == "http.response.start":
                    status = int(message["status"])
                    span.set_attribute("http.response.status_code", status)
                    if status >= 500:
                        span.set_status(Status(StatusCode.ERROR, "HTTP_SERVER_ERROR"))
                await send(message)

            try:
                await self.app(scope, receive, traced_send)
            except BaseException:
                # Propagate cancellation too, without logging exception payloads.
                # 取消与异常仍向上传播；不得导出原始异常中的业务数据或凭据。
                span.set_status(Status(StatusCode.ERROR, "HTTP_EXECUTION_FAILED"))
                span.set_attribute("error.type", "HTTP_EXECUTION_FAILED")
                raise


def configure_telemetry(service_name: str) -> Any:
    """Configure the shared OpenTelemetry provider for generated Agents.

    为生成的 Agent 配置统一 OpenTelemetry Provider；无端点时使用无害的
    no-op provider，不因本地没有 Collector 阻断服务启动。
    """

    try:
        ratio = float(__import__("os").getenv("OTEL_TRACES_SAMPLER_ARG", "1"))
    except ValueError:
        ratio = 1.0
    ratio = min(1.0, max(0.0, ratio))
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    except ImportError as exc:  # pragma: no cover - optional runtime dependency
        if __import__("os").getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
            raise RuntimeError("OpenTelemetry dependencies are not installed") from exc
        return _NoopProvider()

    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name}),
        sampler=ParentBased(TraceIdRatioBased(ratio)),
    )
    if __import__("os").getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or __import__(
        "os"
    ).getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    HTTPXClientInstrumentor().instrument(tracer_provider=provider)
    return provider


class _NoopProvider:
    def shutdown(self) -> None:
        return None


def setup(service_name: str, endpoint: str) -> tuple[Tracer, Any]:
    """Wire OTLP-over-HTTP tracing for one process.

    Returns the tracer and a shutdown callable. The OpenTelemetry SDK is an
    optional dependency: it is imported lazily so the core package stays
    dependency-free, and a missing installation with a configured endpoint
    fails loudly instead of silently dropping telemetry.
    为进程接通 OTLP/HTTP 追踪，返回 tracer 与关闭回调。OpenTelemetry SDK 是
    可选依赖：延迟导入使核心包保持零依赖；已配置端点但未安装依赖时大声失败，
    而不是静默丢弃遥测。
    """
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return NoopTracer(), _no_shutdown
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "OTEL_EXPORTER_OTLP_ENDPOINT is configured but the OpenTelemetry SDK "
            "is not installed; add the agent-platform-sdk[telemetry] extra"
        ) from exc

    exporter = OTLPSpanExporter(endpoint=endpoint)
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    tracer = provider.get_tracer(service_name)

    class _OTelTracer:
        @contextmanager
        def start_span(self, name: str, *attributes: Attribute) -> Iterator[Span]:
            with tracer.start_as_current_span(name) as span:
                for attr in attributes:
                    span.set_attribute(attr.key, attr.value)
                yield span

    return _OTelTracer(), provider.shutdown


def _no_shutdown() -> None:
    return None
