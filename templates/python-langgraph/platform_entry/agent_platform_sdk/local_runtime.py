"""Development-only local run provider shared by all Python Agents.

The production modular-singleton path is owned by the Go platform Execution
Module.  This provider exists only for isolated unit tests and explicit local
development, so Agents do not carry separate execution stores or SQL schemas.
生产模块化单体路径由 Go 中台 Execution Module 负责；本文件仅供单测和明确的
本地开发模式使用，两个 Agent 不再各自复制执行存储和 SQL 表。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from .run_models import ExecutionOutcome

TERMINAL_STATUSES = {"completed", "cancelled", "failed"}
TERMINAL_EVENTS = {"task_completed", "task_cancelled", "task_failed"}
logger = logging.getLogger("agent_platform_sdk.local_runtime")
tracer = trace.get_tracer("agent_platform_sdk.local_runtime")


@dataclass(frozen=True)
class ClaimedExecution:
    task_id: str
    payload: dict[str, Any]
    lease_token: int


class ExecutionStore(Protocol):
    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def ready(self) -> bool: ...
    async def enqueue(self, task_id: str, payload: dict[str, Any]) -> bool: ...
    async def claim(self, owner: str, lease_seconds: int) -> ClaimedExecution | None: ...
    async def renew(self, task_id: str, owner: str, lease_token: int, lease_seconds: int) -> tuple[bool, bool]: ...
    async def finish(self, task_id: str, owner: str, lease_token: int, status: str, event_type: str | None = None, event_payload: dict[str, Any] | None = None) -> bool: ...
    async def release(self, task_id: str, owner: str, lease_token: int) -> bool: ...
    async def append_event(self, task_id: str, event_type: str, payload: dict[str, Any]) -> int: ...
    async def events_after(self, task_id: str, after_seq: int, limit: int = 100) -> list[dict[str, Any]]: ...
    async def request_cancel(self, task_id: str) -> bool: ...
    async def status(self, task_id: str) -> str | None: ...
    async def payload(self, task_id: str) -> dict[str, Any] | None: ...
    async def request_resume(self, task_id: str, resume_input: dict[str, Any]) -> bool: ...


def _canonical_payload(payload: dict[str, Any]) -> tuple[str, str]:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


class MemoryExecutionStore:
    """Bounded in-memory implementation for tests and local development only."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._seq = 0
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def ready(self) -> bool:
        return True

    async def enqueue(self, task_id: str, payload: dict[str, Any]) -> bool:
        raw, digest = _canonical_payload(payload)
        async with self._lock:
            existing = self._jobs.get(task_id)
            if existing is not None:
                if existing["payload_hash"] != digest:
                    raise ValueError("execution task id was reused with different payload")
                return False
            self._jobs[task_id] = {
                "payload": json.loads(raw),
                "payload_hash": digest,
                "status": "queued",
                "owner": "",
                "lease_token": 0,
                "lease_until": None,
                "cancel_requested": False,
            }
            return True

    async def claim(self, owner: str, lease_seconds: int) -> ClaimedExecution | None:
        now = datetime.now(UTC)
        async with self._lock:
            for task_id, job in self._jobs.items():
                expired = job["status"] == "running" and job["lease_until"] and job["lease_until"] <= now
                if job["status"] != "queued" and not expired:
                    continue
                # A zero-second lease is intentionally allowed in tests to
                # force an immediate fencing/reclaim path.
                # 测试允许零秒租约，以便确定性触发 fencing/reclaim 路径。
                job.update(status="running", owner=owner, lease_until=now + timedelta(seconds=max(0, lease_seconds)))
                job["lease_token"] += 1
                return ClaimedExecution(task_id, json.loads(json.dumps(job["payload"])), job["lease_token"])
        return None

    async def renew(self, task_id: str, owner: str, lease_token: int, lease_seconds: int) -> tuple[bool, bool]:
        async with self._lock:
            job = self._jobs.get(task_id)
            if not job or job["status"] != "running" or job["owner"] != owner or job["lease_token"] != lease_token:
                return False, False
            job["lease_until"] = datetime.now(UTC) + timedelta(seconds=max(1, lease_seconds))
            return True, bool(job["cancel_requested"])

    async def finish(self, task_id: str, owner: str, lease_token: int, status: str, event_type: str | None = None, event_payload: dict[str, Any] | None = None) -> bool:
        if status not in TERMINAL_STATUSES | {"waiting_review"}:
            raise ValueError("invalid execution terminal status")
        async with self._lock:
            job = self._jobs.get(task_id)
            if not job or job["owner"] != owner or job["lease_token"] != lease_token:
                return False
            job.update(status=status, owner="", lease_until=None)
            if event_type:
                self._append_event_locked(task_id, event_type, event_payload or {})
            return True

    async def release(self, task_id: str, owner: str, lease_token: int) -> bool:
        async with self._lock:
            job = self._jobs.get(task_id)
            if not job or job["owner"] != owner or job["lease_token"] != lease_token:
                return False
            job.update(status="queued", owner="", lease_until=None)
            return True

    async def append_event(self, task_id: str, event_type: str, payload: dict[str, Any]) -> int:
        async with self._lock:
            if task_id not in self._jobs:
                raise KeyError(task_id)
            return self._append_event_locked(task_id, event_type, payload)

    def _append_event_locked(self, task_id: str, event_type: str, payload: dict[str, Any]) -> int:
        self._seq += 1
        self._events.setdefault(task_id, []).append({"seq": self._seq, "type": event_type, "payload": payload})
        return self._seq

    async def events_after(self, task_id: str, after_seq: int, limit: int = 100) -> list[dict[str, Any]]:
        async with self._lock:
            return [dict(item) for item in self._events.get(task_id, []) if item["seq"] > after_seq][:limit]

    async def request_cancel(self, task_id: str) -> bool:
        async with self._lock:
            job = self._jobs.get(task_id)
            if not job or job["status"] in TERMINAL_STATUSES:
                return False
            if job["status"] in {"queued", "waiting_review"}:
                job.update(status="cancelled", owner="", lease_until=None, cancel_requested=True)
                self._append_event_locked(task_id, "task_cancelled", {})
            else:
                job["cancel_requested"] = True
            return True

    async def status(self, task_id: str) -> str | None:
        async with self._lock:
            job = self._jobs.get(task_id)
            return None if job is None else str(job["status"])

    async def payload(self, task_id: str) -> dict[str, Any] | None:
        async with self._lock:
            job = self._jobs.get(task_id)
            return None if job is None else json.loads(json.dumps(job["payload"], ensure_ascii=False))

    async def request_resume(self, task_id: str, resume_input: dict[str, Any]) -> bool:
        async with self._lock:
            job = self._jobs.get(task_id)
            if not job or job["status"] != "waiting_review":
                return False
            job["payload"]["resume_input"] = json.loads(json.dumps(resume_input, ensure_ascii=False))
            job.update(status="queued", cancel_requested=False)
            self._append_event_locked(task_id, "task_resume_requested", {})
            return True


WorkHandler = Callable[[dict[str, Any]], Awaitable[str | ExecutionOutcome]]


class ExecutionManager:
    """Local development worker; production Docker uses platform dispatcher."""

    def __init__(self, store: ExecutionStore, worker_id: str | None = None, lease_seconds: int = 30, concurrency: int = 4, resume_grace_seconds: float | None = None, event_fallback_seconds: float | None = None) -> None:
        self.store = store
        self.worker_id = worker_id or os.getenv("AGENT_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}"
        self.lease_seconds = max(3, lease_seconds)
        self.concurrency = max(1, concurrency)
        self.resume_grace_seconds = max(0.0, resume_grace_seconds if resume_grace_seconds is not None else float(os.getenv("AGENT_RESUME_GRACE_SECONDS", "2")))
        configured_wait = event_fallback_seconds if event_fallback_seconds is not None else float(os.getenv("AGENT_EVENT_FALLBACK_SECONDS", "15"))
        self.event_fallback_seconds = min(60.0, max(1.0, configured_wait))
        self._work: WorkHandler | None = None
        self._runner: asyncio.Task[None] | None = None
        self._local: dict[str, asyncio.Task[None]] = {}
        self._lease_lost: set[str] = set()
        self._closing = asyncio.Event()
        self._conditions: dict[str, asyncio.Condition] = {}

    async def start(self, work: WorkHandler) -> None:
        self._work = work
        await self.store.open()
        self._runner = asyncio.create_task(self._run(), name=f"agent-worker:{self.worker_id}")

    async def enqueue(self, task_id: str, payload: dict[str, Any]) -> bool:
        return await self.store.enqueue(task_id, payload)

    async def publish(self, task_id: str, event_type: str, payload: dict[str, Any] | None = None) -> int:
        sequence = await self.store.append_event(task_id, event_type, payload or {})
        await self._notify(task_id)
        return sequence

    async def cancel(self, task_id: str) -> bool:
        accepted = await self.store.request_cancel(task_id)
        task = self._local.get(task_id)
        if task is not None and not task.done():
            task.cancel()
        if accepted:
            await self._notify(task_id)
        return accepted

    async def resume(self, task_id: str, resume_input: dict[str, Any]) -> bool:
        deadline = asyncio.get_running_loop().time() + self.resume_grace_seconds
        while True:
            if await self.store.request_resume(task_id, resume_input):
                await self._notify(task_id)
                return True
            if await self.store.status(task_id) != "running" or asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.05)

    async def stream(self, task_id: str, after_seq: int = 0) -> AsyncIterator[dict[str, Any]]:
        cursor = max(0, after_seq)
        condition = self._conditions.setdefault(task_id, asyncio.Condition())
        try:
            while True:
                events = await self.store.events_after(task_id, cursor)
                for item in events:
                    cursor = int(item["seq"])
                    yield item
                    if item["type"] in TERMINAL_EVENTS:
                        return
                status = await self.store.status(task_id)
                if status is None or (status in TERMINAL_STATUSES and not events):
                    return
                async with condition:
                    try:
                        await asyncio.wait_for(condition.wait(), timeout=min(1.0, self.event_fallback_seconds))
                    except TimeoutError:
                        pass
        finally:
            self._conditions.pop(task_id, None)

    async def ready(self) -> bool:
        return await self.store.ready()

    async def scope_matches(self, task_id: str, scope: dict[str, Any]) -> bool:
        payload = await self.store.payload(task_id)
        persisted = ((payload or {}).get("request") or {}).get("scope") or (payload or {}).get("context") or {}
        keys = ("tenant_id", "department_id", "application_id", "agent_instance_id", "installation_id", "agent_id", "agent_version_id", "principal_type", "principal_id", "session_id", "run_id")
        return bool(payload) and all(persisted.get(key) == scope.get(key) for key in keys)

    async def _notify(self, task_id: str) -> None:
        condition = self._conditions.get(task_id)
        if condition is not None:
            async with condition:
                condition.notify_all()

    async def _run(self) -> None:
        while not self._closing.is_set():
            self._local = {key: task for key, task in self._local.items() if not task.done()}
            if len(self._local) >= self.concurrency:
                await asyncio.sleep(0.05)
                continue
            claim = await self.store.claim(self.worker_id, self.lease_seconds)
            if claim is None:
                await asyncio.sleep(0.1)
                continue
            self._local[claim.task_id] = asyncio.create_task(self._execute(claim), name=f"agent-execution:{claim.task_id}")

    async def _execute(self, claim: ClaimedExecution) -> None:
        trace_id = str(claim.payload.get("context", {}).get("trace_id", ""))[:64]
        stage = str(claim.payload.get("state", {}).get("stage", "unknown"))[:64]
        with tracer.start_as_current_span("agent.execution", attributes={"agent.task_id": claim.task_id, "agent.trace_id": trace_id, "agent.stage": stage, "agent.worker_id": self.worker_id}) as span:
            heartbeat = asyncio.create_task(self._heartbeat(claim), name=f"agent-heartbeat:{claim.task_id}")
            status = "failed"
            event_payload: dict[str, Any] = {}
            try:
                if self._work is None:
                    raise RuntimeError("execution worker is not configured")
                outcome = await self._work(claim.payload)
                if isinstance(outcome, ExecutionOutcome):
                    status, event_payload = outcome.status, outcome.event_payload
                else:
                    status = outcome
            except asyncio.CancelledError:
                if self._closing.is_set() or claim.task_id in self._lease_lost:
                    await self.store.release(claim.task_id, self.worker_id, claim.lease_token)
                    heartbeat.cancel()
                    await asyncio.gather(heartbeat, return_exceptions=True)
                    return
                status = "cancelled"
            except Exception as exc:
                status = "failed"
                error_code = "AGENT_EXECUTION_TIMEOUT" if isinstance(exc, TimeoutError) else "AGENT_EXECUTION_FAILED"
                event_payload = {"error_code": error_code}
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, error_code))
                logger.exception("agent execution failed task_id=%s trace_id=%s stage=%s error_code=%s", claim.task_id, trace_id, stage, error_code)
            finally:
                heartbeat.cancel()
                await asyncio.gather(heartbeat, return_exceptions=True)
                if not self._closing.is_set() and claim.task_id not in self._lease_lost:
                    event_type = {"completed": "task_completed", "cancelled": "task_cancelled", "failed": "task_failed", "waiting_review": "task_paused"}.get(status)
                    if event_type:
                        try:
                            persisted = await self.store.finish(claim.task_id, self.worker_id, claim.lease_token, status, event_type, event_payload)
                            if not persisted:
                                span.set_status(Status(StatusCode.ERROR, "EXECUTION_LEASE_FENCED"))
                        except Exception as exc:
                            span.record_exception(exc)
                            span.set_status(Status(StatusCode.ERROR, "EXECUTION_TERMINAL_PERSIST_FAILED"))
                            logger.exception("execution terminal persistence failed task_id=%s trace_id=%s stage=%s", claim.task_id, trace_id, stage)
                        await self._notify(claim.task_id)
                self._lease_lost.discard(claim.task_id)

    async def _heartbeat(self, claim: ClaimedExecution) -> None:
        current = asyncio.current_task()
        while True:
            await asyncio.sleep(max(1.0, self.lease_seconds / 3))
            try:
                owned, cancel_requested = await self.store.renew(claim.task_id, self.worker_id, claim.lease_token, self.lease_seconds)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._lease_lost.add(claim.task_id)
                logger.exception("execution heartbeat failed task_id=%s worker_id=%s", claim.task_id, self.worker_id)
                if current is not None:
                    current.cancel()
                return
            if not owned or cancel_requested:
                if not owned:
                    self._lease_lost.add(claim.task_id)
                if current is not None:
                    current.cancel()
                return

    async def close(self) -> None:
        self._closing.set()
        if self._runner is not None:
            self._runner.cancel()
            await asyncio.gather(self._runner, return_exceptions=True)
        tasks = [task for task in self._local.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self.store.close()


def build_execution_store() -> ExecutionStore:
    """Build only the SDK's local test provider; production must use platform."""

    mode = os.getenv("EXECUTION_BACKEND", "memory").strip().lower()
    if mode != "memory":
        raise RuntimeError("local execution backend was removed; configure PLATFORM_RUN_BASE_URL")
    if os.getenv("APP_ENV", "dev").strip().lower() in {"prod", "production"}:
        raise RuntimeError("EXECUTION_BACKEND=memory is forbidden in production")
    return MemoryExecutionStore()


def build_local_run_provider(
    *, lease_seconds: int = 30, concurrency: int = 4
) -> ExecutionManager:
    """Build the SDK-owned development provider for an isolated Agent.

    Agent entrypoints call this factory instead of importing or constructing
    ``ExecutionManager``/``ExecutionStore`` directly.  Production containers
    must use the platform provider; this seam exists only for explicit local
    development and unit tests. / Agent 入口只调用此工厂，不直接装配执行器。
    """

    return ExecutionManager(
        build_execution_store(),
        lease_seconds=lease_seconds,
        concurrency=concurrency,
    )
