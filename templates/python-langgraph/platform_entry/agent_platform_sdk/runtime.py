"""Shared Agent runtime lifecycle for the modular-singleton deployment.

The Agent package supplies only its Graph builder, verifier factory and
business worker callback.  Provider selection, checkpoint lifecycle,
telemetry, the RunGateway and the Agent Execution v2 gRPC transport are owned here so
two Agents cannot slowly grow different bootstrap semantics.

Agent 包只提供业务 Graph 构造器、上下文验证器和业务 Worker；Provider 选择、
Checkpoint 生命周期、遥测、RunGateway 以及 Execution v2 gRPC Transport 统一由 SDK 托管，避免
两个 Agent 的启动代码逐渐分叉。
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
import os
from typing import Any

from .checkpoint import close_checkpointer, get_checkpointer
from .platform_run import PlatformProjectionProvider, PlatformRunClient
from .run_gateway import NoopRunProvider, RunGateway
from .runtime_mode import RuntimeModeError, resolve_runtime_mode
from .telemetry import configure_telemetry


GraphBuilder = Callable[[Any], Any]
VerifierFactory = Callable[[], Any]
WorkCallback = Callable[[dict[str, Any]], Awaitable[Any]]


@dataclass(slots=True)
class AgentRuntime:
    """All process-scoped resources owned by one Agent instance."""

    graph: Any
    run_gateway: RunGateway
    verifier: Any
    tracer_provider: Any
    grpc_server: Any | None

    async def close(self) -> None:
        """Close resources in reverse dependency order.

        依赖逆序关闭资源，任何单个清理失败都不能阻止其余资源释放。
        """

        if self.grpc_server is not None:
            with suppress(Exception):
                await self.grpc_server.stop(grace=5)
            self.grpc_server = None
        with suppress(Exception):
            await self.run_gateway.close()
        with suppress(Exception):
            await close_checkpointer()
        if self.tracer_provider is not None:
            with suppress(Exception):
                self.tracer_provider.shutdown()
            self.tracer_provider = None


def _build_local_provider(*, lease_seconds: int, concurrency: int) -> Any:
    """Load the development-only provider lazily.

    本地 Provider 仅在显式 development/local 模式导入，生产进程不会持有
    第二套本地执行账本。
    """

    from .dev_runtime import build_local_run_provider

    return build_local_run_provider(
        lease_seconds=lease_seconds,
        concurrency=concurrency,
    )


async def start_agent_runtime(
    *,
    agent_id: str,
    graph_builder: GraphBuilder,
    verifier_factory: VerifierFactory,
    work: WorkCallback,
    grpc_port: int,
    grpc_http_base_url: str,
    local_concurrency: int,
    enable_grpc_transport: bool = True,
) -> AgentRuntime:
    """Construct the standard runtime used by every Python Agent.

    The function is deliberately dependency-injected at the business edges;
    a future remote Worker or a different language Agent can use the same
    lifecycle contract without copying this bootstrap code.

    该函数只在业务边界注入依赖；未来替换为远程 Worker 或其他语言 Agent 时，
    仍可复用同一生命周期契约，而不需要复制启动逻辑。
    """

    try:
        runtime_mode = resolve_runtime_mode()
    except RuntimeModeError as exc:
        raise RuntimeError(str(exc)) from exc

    tracer_provider = configure_telemetry(agent_id)
    gateway: RunGateway | None = None
    grpc_server: Any | None = None
    try:
        verifier = verifier_factory()
        graph = graph_builder(await get_checkpointer())
        platform_base_url = runtime_mode.platform_base_url
        if platform_base_url:
            platform_executor = runtime_mode.executor == "platform"
            if platform_executor:
                local_provider = NoopRunProvider()
            else:
                local_provider = _build_local_provider(
                    lease_seconds=int(
                        os.getenv("AGENT_EXECUTION_LEASE_SECONDS", "30")
                    ),
                    concurrency=local_concurrency,
                )
            platform_token = os.getenv("PLATFORM_RUN_TOKEN", "").strip()
            if not platform_token:
                raise RuntimeError(
                    "PLATFORM_RUN_TOKEN is required with PLATFORM_RUN_BASE_URL"
                )
            gateway = RunGateway(
                PlatformProjectionProvider(
                    local_provider,
                    PlatformRunClient(platform_base_url, platform_token),
                    agent_endpoint=os.getenv("PLATFORM_AGENT_ENDPOINT", "").strip(),
                    local_enqueue=not platform_executor,
                )
            )
        else:
            gateway = RunGateway(
                _build_local_provider(
                    lease_seconds=int(
                        os.getenv("AGENT_EXECUTION_LEASE_SECONDS", "30")
                    ),
                    concurrency=local_concurrency,
                )
            )

        await gateway.start(work)
        if enable_grpc_transport:
            # Load the v2 gRPC transport only when this Agent exposes it; HTTP-only
            # Agents do not need grpcio during module import.
            # 仅在 Agent 启用 v2 gRPC Transport 时加载，纯 HTTP Agent 无需导入 grpcio。
            from .grpc_bridge import start_grpc_bridge

            http_port = os.environ.get("AGENT_HTTP_PORT", "").strip()
            if http_port:
                if not http_port.isdigit() or not 1 <= int(http_port) <= 65535:
                    raise ValueError("invalid Agent HTTP port")
                grpc_http_base_url = f"http://127.0.0.1:{int(http_port)}"
            grpc_server = await start_grpc_bridge(grpc_port, grpc_http_base_url)
        return AgentRuntime(
            graph=graph,
            run_gateway=gateway,
            verifier=verifier,
            tracer_provider=tracer_provider,
            grpc_server=grpc_server,
        )
    except Exception:
        if grpc_server is not None:
            with suppress(Exception):
                await grpc_server.stop(grace=5)
        if gateway is not None:
            with suppress(Exception):
                await gateway.close()
        with suppress(Exception):
            await close_checkpointer()
        with suppress(Exception):
            tracer_provider.shutdown()
        raise


__all__ = ["AgentRuntime", "start_agent_runtime"]
