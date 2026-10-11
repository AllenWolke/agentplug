"""Small Agent App Factory shared by every language-agnostic Python Agent.

统一 Agent App Factory：Agent 只提供业务 Hook，Server、Security、RunStore
和 Telemetry 仍由 SDK/平台治理。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .lifecycle import RunStore
from .server import ExecutionServer, InvokeHandler, RunHandler, ServerConfig
from .tracing import Tracer


@dataclass(frozen=True, slots=True)
class AgentApp:
    """Configured SDK application; it has no Agent-specific routing code."""

    server: ExecutionServer

    def handler(self):
        """Return the standard HTTP handler used by local or remote startup."""
        return self.server.handler()

    def serve(self, address: tuple[str, int]):
        """Start a ThreadingHTTPServer with the standard lifecycle surface."""
        return self.server.serve(address)


def create_agent_app(
    *,
    public_key: Ed25519PublicKey,
    issuer: str,
    audience: str,
    agent_id: str,
    store: RunStore,
    capabilities: list[str] | None = None,
    agent_version: str = "0.1.0",
    tracer: Tracer | None = None,
    invoke: InvokeHandler | None = None,
    run: RunHandler | None = None,
    now: Callable[[], int] | None = None,
    validate_input: Callable[[Any], None] | None = None,
) -> AgentApp:
    """Build the standard Execution v2 surface from business hooks.

    / 通过业务 Hook 创建标准 Execution v2 入口；不允许 Agent 自己复制认证、
    状态机、事件流或遥测接线。
    """
    config = ServerConfig(
        public_key=public_key,
        issuer=issuer,
        audience=audience,
        agent_id=agent_id,
        store=store,
        capabilities=capabilities or ["invoke"],
        agent_version=agent_version,
        tracer=tracer,
        invoke=invoke,
        run=run,
        now=now,
        validate_input=validate_input,
    )
    return AgentApp(server=ExecutionServer(config))
