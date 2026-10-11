"""Framework-neutral async/ASGI Agent Factory.

The SDK offers a separate synchronous factory for synchronous hooks.
LangGraph Agents use this async boundary so their coroutine hooks do not need to
reimplement authentication, manifest, health and protocol error handling.
同步 Factory 用于同步 Hook；LangGraph Agent 使用此异步边界，避免重新实现
认证、Manifest、健康检查和协议错误处理。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

AsyncHook = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class AsyncFactoryError(ValueError):
    """Raised when async Agent hooks do not satisfy the manifest contract."""


@dataclass(frozen=True, slots=True)
class AsyncAgentHooks:
    agent_id: str
    version: str
    capabilities: tuple[str, ...]
    authorize: AsyncHook
    invoke: AsyncHook | None = None
    run: AsyncHook | None = None
    resume: AsyncHook | None = None
    cancel: AsyncHook | None = None
    events: AsyncHook | None = None
    max_body_bytes: int = 1_048_576


class AsyncAgentApp:
    """A small ASGI adapter with one framework-neutral business seam."""

    def __init__(self, hooks: AsyncAgentHooks) -> None:
        if not hooks.agent_id or not hooks.version or not hooks.capabilities:
            raise AsyncFactoryError("agent id, version and capabilities are required")
        if hooks.max_body_bytes <= 0:
            raise AsyncFactoryError("max body size must be positive")
        if "invoke" in hooks.capabilities and hooks.invoke is None:
            raise AsyncFactoryError("invoke capability requires invoke hook")
        lifecycle = {"run", "resume", "cancel", "events"}
        if "run" in hooks.capabilities and not all(
            getattr(hooks, name) is not None for name in lifecycle
        ):
            raise AsyncFactoryError("run capability requires complete lifecycle hooks")
        self.hooks = hooks

    def manifest(self) -> dict[str, Any]:
        return {
            "manifest_version": "agent-manifest/v1",
            "agent_id": self.hooks.agent_id,
            "version": self.hooks.version,
            "capabilities": list(self.hooks.capabilities),
            "execution_protocols": ["agent-execution/v2"],
        }

    def asgi(self) -> Callable[..., Awaitable[None]]:
        async def application(scope: dict[str, Any], receive: Any, send: Any) -> None:
            method = scope.get("method", "GET").upper()
            path = str(scope.get("path", ""))
            if method == "GET" and path in {"/health/live", "/health/ready"}:
                await self._respond(send, 200, {"status": "live" if path.endswith("live") else "ready"})
                return
            if method == "GET" and path == "/.well-known/agent-manifest.json":
                await self._respond(send, 200, self.manifest())
                return
            if method != "POST":
                await self._respond(send, 404, {"code": "NOT_FOUND"})
                return
            try:
                payload = await self._read_json(scope, receive)
                await self.hooks.authorize(payload)
                hook = self._hook_for(path)
                if hook is None:
                    await self._respond(send, 404, {"code": "NOT_FOUND"})
                    return
                result = await hook(payload)
                await self._respond(send, 200, result)
            except AsyncFactoryError as exc:
                await self._respond(send, 400, {"code": "INVALID_REQUEST", "message": str(exc)})
            except PermissionError:
                await self._respond(send, 401, {"code": "UNAUTHORIZED"})
            except json.JSONDecodeError:
                await self._respond(send, 400, {"code": "INVALID_JSON"})
            except Exception:
                # Never leak model/provider or request payload details.
                # 不把模型/Provider 或请求原文泄露给调用方。
                await self._respond(send, 500, {"code": "AGENT_EXECUTION_FAILED"})

        return application

    def _hook_for(self, path: str) -> AsyncHook | None:
        if path.endswith("/invoke"):
            return self.hooks.invoke
        if path.endswith("/runs"):
            return self.hooks.run
        if path.endswith("/resume"):
            return self.hooks.resume
        if path.endswith("/cancel"):
            return self.hooks.cancel
        if path.endswith("/events"):
            return self.hooks.events
        return None

    async def _read_json(self, scope: dict[str, Any], receive: Any) -> dict[str, Any]:
        length = next((value for key, value in scope.get("headers", []) if key.lower() == b"content-length"), None)
        if length is not None:
            try:
                declared = int(length)
            except (TypeError, ValueError) as exc:
                raise AsyncFactoryError("content-length is invalid") from exc
            if declared < 0 or declared > self.hooks.max_body_bytes:
                raise AsyncFactoryError("request body is too large")
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > self.hooks.max_body_bytes:
                raise AsyncFactoryError("request body is too large")
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        value = json.loads(b"".join(chunks))
        if not isinstance(value, dict):
            raise AsyncFactoryError("request JSON must be an object")
        return value

    @staticmethod
    async def _respond(send: Any, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": encoded})


def create_async_agent_app(**kwargs: Any) -> AsyncAgentApp:
    """Create the async Factory product used by FastAPI/Starlette adapters."""

    return AsyncAgentApp(AsyncAgentHooks(**kwargs))
