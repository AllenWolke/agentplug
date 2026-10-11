"""The SDK's minimal tracing seam.

The core package stays dependency-free; :mod:`agent_platform_sdk.telemetry`
provides the OpenTelemetry implementation and injects it here.
SDK 的最小追踪接缝：核心包保持零依赖，由 telemetry 模块提供 OpenTelemetry
实现并注入。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Protocol
from contextlib import AbstractContextManager


@dataclass(frozen=True, slots=True)
class Attribute:
    """One string key/value label attached to a span.

    Sensitive claims (tokens, tenant ids) must never become attributes.
    附加到 Span 的字符串键值；敏感声明（令牌、租户 ID）禁止作为属性。
    """

    key: str
    value: str


class Span(Protocol):
    def end(self) -> None: ...


class Tracer(Protocol):
    def start_span(
        self, name: str, *attributes: Attribute
    ) -> AbstractContextManager[Span]: ...


class _NoopSpan:
    def end(self) -> None:
        return None


class NoopTracer:
    """The fail-safe default: no telemetry leaves the process when no tracer
    is configured. / 失败安全默认值：未配置追踪器时不产生任何遥测输出。
    """

    @contextmanager
    def start_span(self, name: str, *attributes: Attribute) -> Iterator[_NoopSpan]:
        yield _NoopSpan()
