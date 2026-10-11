from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol


class RunProvider(Protocol):
    """Durable run provider implemented by platform Local/Remote adapters."""

    async def start(self, work: Callable[[dict[str, Any]], Awaitable[Any]]) -> None: ...
    async def close(self) -> None: ...
    async def ready(self) -> bool: ...
    async def enqueue(self, run_id: str, payload: dict[str, Any]) -> bool: ...
    async def publish(self, run_id: str, event_type: str, payload: dict[str, Any] | None = None) -> int: ...
    async def cancel(self, run_id: str) -> bool: ...
    async def resume(self, run_id: str, resume_input: dict[str, Any]) -> bool: ...
    # Async-generator methods are regular callables that return an
    # AsyncIterator; declaring ``async def`` here would make mypy treat the
    # result as a coroutine containing an iterator. / 异步生成器调用后直接
    # 返回 AsyncIterator，不能在 Protocol 中误声明为 Coroutine。
    def stream(self, run_id: str, after_seq: int = 0) -> AsyncIterator[dict[str, Any]]: ...
    async def scope_matches(self, run_id: str, scope: dict[str, Any]) -> bool: ...


class NoopRunProvider:
    """Platform-worker mode provider with no local execution ledger.

    平台 Worker 模式下不启动第二个本地队列或执行账本；生命周期事实由
    ``PlatformProjectionProvider`` 负责，这个实现只保留 SDK 端口兼容性。
    """

    async def start(self, work: Callable[[dict[str, Any]], Awaitable[Any]]) -> None:
        return None

    async def close(self) -> None:
        return None

    async def ready(self) -> bool:
        return True

    async def enqueue(self, run_id: str, payload: dict[str, Any]) -> bool:
        return False

    async def publish(
        self, run_id: str, event_type: str, payload: dict[str, Any] | None = None
    ) -> int:
        return 0

    async def cancel(self, run_id: str) -> bool:
        return True

    async def resume(self, run_id: str, resume_input: dict[str, Any]) -> bool:
        return True

    async def scope_matches(self, run_id: str, scope: dict[str, Any]) -> bool:
        return True

    async def stream(
        self, run_id: str, after_seq: int = 0
    ) -> AsyncIterator[dict[str, Any]]:
        if False:  # pragma: no cover - keep this method an async generator.
            yield {}


@dataclass(slots=True)
class RunGateway:
    """Shared SDK boundary for run lifecycle and event subscriptions.

    Agent code supplies business work only; a future platform LocalAdapter or
    remote HTTP/gRPC provider can replace the selected local or platform provider.
    Agent 代码只提供业务 work，后续可替换为平台本地或远程 Provider。
    """

    provider: RunProvider

    async def start(self, work: Callable[[dict[str, Any]], Awaitable[Any]]) -> None:
        await self.provider.start(work)

    async def close(self) -> None:
        await self.provider.close()

    async def ready(self) -> bool:
        return await self.provider.ready()

    async def enqueue(self, run_id: str, payload: dict[str, Any]) -> bool:
        return await self.provider.enqueue(run_id, payload)

    async def publish(
        self, run_id: str, event_type: str, payload: dict[str, Any] | None = None
    ) -> int:
        return await self.provider.publish(run_id, event_type, payload)

    async def cancel(self, run_id: str) -> bool:
        return await self.provider.cancel(run_id)

    async def resume(self, run_id: str, resume_input: dict[str, Any]) -> bool:
        return await self.provider.resume(run_id, resume_input)

    async def scope_matches(self, run_id: str, scope: dict[str, Any]) -> bool:
        return await self.provider.scope_matches(run_id, scope)

    def stream(self, run_id: str, after_seq: int = 0) -> AsyncIterator[dict[str, Any]]:
        return self.provider.stream(run_id, after_seq)
