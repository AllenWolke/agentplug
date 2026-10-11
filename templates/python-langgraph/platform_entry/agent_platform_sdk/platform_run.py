"""Platform-backed Run projection for the modular-monolith transition.

模块化单体迁移期间，业务 Worker 仍由 Agent 进程执行，但 Run 的创建、
Scope 校验、状态和事件会投影到平台的持久化 Execution Module。这样可以
在不改变业务 Graph 的情况下先统一生命周期边界，后续再把 Worker 队列替换
为平台 Supervisor/Queue。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .run_gateway import RunProvider
from .cancellation import read_cancellation_state

logger = logging.getLogger("agent_platform_sdk.platform_run")


class PlatformRunClientProtocol(Protocol):
    async def create(self, payload: dict[str, Any]) -> dict[str, Any]: ...

    async def get(self, run_id: str, scope: dict[str, Any]) -> dict[str, Any]: ...

    async def transition(
        self, run_id: str, scope: dict[str, Any], from_status: str, to_status: str, revision: int
    ) -> dict[str, Any]: ...

    async def append_event(
        self, run_id: str, scope: dict[str, Any], event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]: ...

    async def events(
        self, run_id: str, scope: dict[str, Any], after_seq: int
    ) -> list[dict[str, Any]]: ...

    async def ready(self) -> bool: ...


class PlatformRunError(RuntimeError):
    """Stable error for platform lifecycle failures."""


@dataclass(slots=True)
class PlatformRunClient:
    """Small dependency-free HTTP client for the platform execution API."""

    base_url: str
    internal_token: str
    agent_endpoint: str = ""
    timeout: float = 5.0
    _headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.base_url:
            raise ValueError("platform run base URL is required")
        if not self.internal_token:
            raise ValueError("platform run internal token is required")

    async def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        headers_extra: dict[str, str] | None = None,
    ) -> Any:
        raw = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.internal_token}",
            **self._headers,
            **(headers_extra or {}),
        }
        if raw is not None:
            headers["Content-Type"] = "application/json"

        def call() -> Any:
            request = Request(f"{self.base_url}{path}", data=raw, headers=headers, method=method)
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    content = response.read(4 * 1024 * 1024)
                    return json.loads(content.decode("utf-8")) if content else None
            except HTTPError as exc:
                content = exc.read(64 * 1024)
                try:
                    details = json.loads(content.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    details = {"status": exc.code}
                raise PlatformRunError(f"platform execution HTTP {exc.code}: {details}") from exc
            except (URLError, TimeoutError, OSError) as exc:
                raise PlatformRunError(f"platform execution request failed: {exc}") from exc

        return await asyncio.to_thread(call)

    async def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", "/modules/execution/platform/runs", payload)

    async def get(self, run_id: str, scope: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "X-Tenant-ID": str(scope.get("tenant_id", "")),
            "X-Department-ID": str(scope.get("department_id", "")),
            "X-Application-ID": str(scope.get("application_id", "")),
            "X-Agent-Instance-ID": str(scope.get("agent_instance_id", "")),
            "X-Installation-ID": str(scope.get("installation_id", "")),
            "X-Agent-ID": str(scope.get("agent_id", "")),
            "X-Principal-ID": str(scope.get("principal_id", "")),
            "X-Principal-Type": str(scope.get("principal_type", "")),
            "X-Installation-ID": str(scope.get("installation_id", "")),
            "X-Agent-Version-ID": str(scope.get("agent_version_id", "")),
            "X-Session-ID": str(scope.get("session_id", "")),
            "X-Authorization-Epoch": str(scope.get("authorization_epoch", 0)),
            "X-Trace-ID": str(scope.get("trace_id", "")),
        }
        return await self._request("GET", f"/modules/execution/platform/runs/{run_id}", None, headers)

    async def transition(
        self, run_id: str, scope: dict[str, Any], from_status: str, to_status: str, revision: int
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/modules/execution/platform/runs/{run_id}/transition",
            {"scope": scope, "from": from_status, "to": to_status, "expected_revision": revision},
        )

    async def append_event(
        self, run_id: str, scope: dict[str, Any], event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/modules/execution/platform/runs/{run_id}/events",
            {"scope": scope, "event_type": event_type, "payload": payload},
        )

    async def events(
        self, run_id: str, scope: dict[str, Any], after_seq: int
    ) -> list[dict[str, Any]]:
        result = await self._request(
            "POST",
            f"/modules/execution/platform/runs/{run_id}/events",
            {"scope": scope, "after_seq": after_seq},
        )
        return list(result or [])

    async def ready(self) -> bool:
        try:
            await self._request("GET", "/health/ready", None)
            return True
        except PlatformRunError:
            return False


@dataclass(slots=True)
class PlatformProjectionProvider:
    """Project local Agent work onto platform-owned durable Run metadata.

    The local provider remains the worker queue in this transitional phase. No
    business state is duplicated here; the platform projection is a lifecycle
    source for authorization, recovery and cross-process event subscriptions.
    """

    local: RunProvider
    platform: PlatformRunClientProtocol
    agent_endpoint: str = ""
    local_enqueue: bool = True
    poll_interval: float = 0.2
    _scopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    _revisions: dict[str, int] = field(default_factory=dict)
    _statuses: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def _platform_scope(scope: dict[str, Any]) -> dict[str, Any]:
        """Project the SDK envelope onto the strict Go platform Scope DTO.

        The Python wire model also carries forward-compatible parent/delegation
        fields.  The current Go HTTP DTO deliberately rejects unknown JSON, so
        those transport extensions must stop at this adapter boundary rather
        than making a valid Agent request fail with HTTP 400.
        / Python 信封包含可前向兼容的父运行和委派字段；当前 Go DTO 严格拒绝
        未知 JSON，必须在 Adapter 边界裁剪扩展字段，不能让合法请求被 400 拒绝。
        """

        keys = (
            "tenant_id", "department_id", "application_id", "agent_instance_id", "installation_id",
            "agent_id", "principal_id", "principal_type", "installation_id",
            "agent_version_id", "session_id", "run_id", "authorization_epoch",
            "trace_id",
        )
        return {key: scope.get(key, "") for key in keys}

    async def start(self, work: Callable[[dict[str, Any]], Awaitable[Any]]) -> None:
        await self.local.start(work)

    async def close(self) -> None:
        await self.local.close()

    async def ready(self) -> bool:
        return await self.local.ready() and await self.platform.ready()

    @staticmethod
    def _request_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
        request = payload.get("request")
        if isinstance(request, dict):
            return request
        context = payload.get("context")
        if isinstance(context, dict):
            return {"scope": context}
        raise ValueError("execution payload does not contain a platform scope")

    async def enqueue(self, run_id: str, payload: dict[str, Any]) -> bool:
        request = self._request_from_payload(payload)
        scope = self._platform_scope(dict(request.get("scope") or {}))
        if scope.get("run_id") != run_id:
            raise ValueError("run id and scope.run_id mismatch")
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        create_payload = {
            "run_id": run_id,
            "scope": scope,
            "agent_version_id": scope.get("agent_version_id", ""),
            "idempotency_key": request.get("idempotency_key", run_id),
            "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "request": request,
            "agent_endpoint": self.agent_endpoint,
        }
        created = await self.platform.create(create_payload)
        self._scopes[run_id] = scope
        self._revisions[run_id] = int(created.get("revision", 1))
        self._statuses[run_id] = str(created.get("status", "accepted"))
        if not self.local_enqueue:
            return True
        return await self.local.enqueue(run_id, payload)

    async def _current(self, run_id: str, scope: dict[str, Any]) -> tuple[str, int]:
        """Refresh status/revision after restart before a lifecycle mutation.

        重启后本地缓存为空，任何状态迁移前都必须从平台读取当前 revision，
        避免使用陈旧 revision 覆盖另一个 Worker 的更新。
        """

        current = await self.platform.get(run_id, scope)
        status = str(current.get("status", ""))
        revision = int(current.get("revision", 0))
        if not status or revision <= 0:
            raise PlatformRunError("platform execution returned incomplete lifecycle state")
        self._statuses[run_id] = status
        self._revisions[run_id] = revision
        return status, revision

    async def _transition_for_event(self, run_id: str, scope: dict[str, Any], event_type: str) -> None:
        target = {
            "started": "running",
            "task_started": "running",
            "waiting_review": "waiting",
            "task_paused": "waiting",
            "completed": "succeeded",
            "task_completed": "succeeded",
            "failed": "failed",
            "task_failed": "failed",
        }.get(event_type)
        if target is None:
            return
        current, revision = await self._current(run_id, scope)
        if current == target:
            return
        if current not in {"accepted", "running", "waiting"}:
            raise PlatformRunError(f"cannot project {event_type} from platform status {current}")
        updated = await self.platform.transition(run_id, scope, current, target, revision)
        self._statuses[run_id] = str(updated.get("status", target))
        self._revisions[run_id] = int(updated.get("revision", revision + 1))

    async def publish(
        self, run_id: str, event_type: str, payload: dict[str, Any] | None = None
    ) -> int:
        scope = self._scopes.get(run_id)
        if scope is None:
            raise ValueError("unknown run scope")
        if event_type in {"cancelled", "task_cancelled"}:
            # Local execution exit cannot prove business-effect compensation.
            # The platform coordinator alone publishes final cancellation.
            current, _ = await self._current(run_id, scope)
            if current not in {"cancelling", "cancelled"}:
                raise PlatformRunError("platform cancellation intent is required before stop projection")
            event_type = "execution_stopped"
        await self._transition_for_event(run_id, scope, event_type)
        event = await self.platform.append_event(run_id, scope, event_type, payload or {})
        await self.local.publish(run_id, event_type, payload or {})
        return int(event.get("seq", 0))

    async def cancel(self, run_id: str) -> bool:
        scope = self._scopes.get(run_id)
        if scope is None:
            return False
        current = await self.platform.get(run_id, scope)
        status = str(current.get("status", ""))
        self._statuses[run_id] = status
        self._revisions[run_id] = int(current.get("revision", 0))
        if status == "cancelling":
            # Invoked by the platform stop control path. Do not recursively
            # request platform cancellation or forge the final outcome.
            return await self.local.cancel(run_id)
        if status == "cancelled":
            evidence = read_cancellation_state(status, current.get("cancellation"))
            return evidence is not None and evidence.complete
        return False

    async def resume(self, run_id: str, resume_input: dict[str, Any]) -> bool:
        scope = self._scopes.get(run_id)
        if scope is None:
            return False
        current = await self.platform.get(run_id, scope)
        self._statuses[run_id] = str(current.get("status", ""))
        self._revisions[run_id] = int(current.get("revision", 0))
        if str(current.get("status")) != "waiting":
            return False
        # The platform Dispatcher owns the waiting->running CAS when it sends
        # an internal resume request. Do not repeat the transition from the
        # Agent process; the marker is added only by that trusted dispatcher.
        # 平台 Dispatcher 派发内部恢复请求时已经完成 CAS；Agent 不能重复迁移，
        # 该标记只由受信平台 Dispatcher 注入。
        if bool(resume_input.get("_platform_dispatch")):
            return await self.local.resume(run_id, resume_input)
        await self.platform.transition(run_id, scope, "waiting", "running", int(current["revision"]))
        return await self.local.resume(run_id, resume_input)

    async def scope_matches(self, run_id: str, scope: dict[str, Any]) -> bool:
        try:
            platform_scope = self._platform_scope(scope)
            current = await self.platform.get(run_id, platform_scope)
        except PlatformRunError:
            return False
        matches = current.get("scope") == platform_scope
        if matches:
            self._scopes[run_id] = platform_scope
            self._statuses[run_id] = str(current.get("status", ""))
            self._revisions[run_id] = int(current.get("revision", 0))
        return matches

    async def stream(self, run_id: str, after_seq: int = 0) -> AsyncIterator[dict[str, Any]]:
        scope = self._scopes.get(run_id)
        if scope is None:
            return
        cursor = after_seq
        terminal = {"completed", "failed", "task_completed", "task_failed"}
        while True:
            events = await self.platform.events(run_id, scope, cursor)
            for item in events:
                cursor = int(item["seq"])
                normalized = {
                    "seq": cursor,
                    "type": item.get("event_type", item.get("type", "progress")),
                    "payload": item.get("payload", {}),
                }
                yield normalized
                if normalized["type"] in {"cancelled", "task_cancelled"} or (
                    normalized["type"] == "status" and normalized["payload"].get("to") == "cancelled"
                ):
                    # Old history/local stop events are insufficient. Wait for
                    # the current authorized platform completion projection.
                    current = await self.platform.get(run_id, scope)
                    evidence = read_cancellation_state(str(current.get("status", "")), current.get("cancellation"))
                    if evidence is not None and evidence.complete:
                        return
                if normalized["type"] in terminal:
                    return
            if events and any(item.get("event_type", item.get("type")) in terminal for item in events):
                return
            await asyncio.sleep(max(0.05, self.poll_interval))
