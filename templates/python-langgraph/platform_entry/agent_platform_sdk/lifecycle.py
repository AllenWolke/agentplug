"""Run lifecycle SPI: the SDK owns the run state machine so generated Agents
never build a parallel one; business code only implements the RunHandler seam.

运行生命周期 SPI：状态机由 SDK 持有，生成 Agent 不得自建；业务代码只实现
RunHandler 接缝。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .models import (MAX_SAFE_EVENT_SEQUENCE, AppError, ExecuteRequest, ExecutionEvent,
                     ScopeKey, validate_event_cursor)

RUNNING = "running"
WAITING = "waiting"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"

TERMINAL_STATUSES = frozenset({SUCCEEDED, FAILED, CANCELLED})

# SSE event types carried by the events endpoint. / events 端点输出的 SSE 事件类型。
EVENT_ACCEPTED = "accepted"
EVENT_STARTED = "started"
EVENT_PROGRESS = "progress"
EVENT_WAITING = "waiting"
EVENT_ARTIFACT = "artifact"
EVENT_COMPLETED = "completed"
EVENT_FAILED = "failed"
EVENT_CANCELLED = "cancelled"

# The bundled memory store must be labelled this way in every manifest that
# uses it, so operators can reject it before L2/L3 deployment.
# 内置内存存储在 manifest 中必须如此标注，运维可在 L2/L3 前拒绝该配置。
MEMORY_RUN_STORE_LABEL = "memory-dev-only(L2/L3 forbidden)"

# Reserve a deterministic sequence interval for each signed execution
# revision.  The upper bound is the largest integer JavaScript can represent
# exactly, which keeps SSE IDs safe in browsers.
EVENT_SEQUENCE_WIDTH = 1 << 20
MAX_EXECUTION_REVISION = 1 << 33
MAX_EVENT_SEQUENCE = MAX_SAFE_EVENT_SEQUENCE


def generation_sequence_range(execution_revision: int) -> tuple[int, int]:
    """Return the inclusive ``(base, limit)`` for one verified generation."""
    if (type(execution_revision) is not int
            or not 1 <= execution_revision <= MAX_EXECUTION_REVISION):
        raise InvalidTransitionError("execution revision is outside event sequence range")
    base = (execution_revision - 1) * EVENT_SEQUENCE_WIDTH
    limit = base + EVENT_SEQUENCE_WIDTH - 1
    if limit > MAX_EVENT_SEQUENCE:
        raise InvalidTransitionError("execution revision is outside event sequence range")
    return base, limit


class RunUnknownError(Exception):
    """The referenced run does not exist. / 目标运行不存在。"""


class IdempotencyConflictError(Exception):
    """The run id was reused with a different idempotency key. / run_id 被不同的幂等键复用。"""


class InvalidTransitionError(Exception):
    """The run state transition is invalid. / 运行状态迁移不合法。"""


@dataclass(frozen=True, slots=True)
class RunRecord:
    """Immutable view of one run returned by a RunStore. / RunStore 返回的单次运行的只读视图。"""

    run_id: str
    scope: ScopeKey
    idempotency_key: str
    status: str
    output: dict[str, Any] = field(default_factory=dict)
    error: AppError | None = None
    events: tuple[ExecutionEvent, ...] = ()


class EventSink(Protocol):
    """Lets a run handler append progress events through the store.

    让运行处理器通过 Store 追加进度事件。
    """

    def append(self, event_type: str, payload: dict[str, Any]) -> None: ...


class RunStore(Protocol):
    """Platform run state SPI.

    L2/L3 deployments must provide a scoped, durable implementation (tenant
    isolation, restart recovery); the bundled MemoryRunStore is explicitly
    forbidden there. / 平台运行状态 SPI：L2/L3 必须提供带 Scope 隔离与重启
    恢复的持久化实现；内置 MemoryRunStore 显式禁止用于 L2/L3。
    """

    def start_run(self, request: ExecuteRequest) -> tuple[RunRecord, bool]:
        """Create a run or return the existing record for the same run_id and
        idempotency key. A different key on the same run_id is a conflict.
        创建运行；同 run_id 且同幂等键时返回既有记录，幂等键不同则视为冲突。
        """

    def get_run(self, run_id: str) -> RunRecord | None: ...

    def append_event(self, run_id: str, event_type: str, payload: dict[str, Any]) -> ExecutionEvent:
        """Append one event with the next per-run sequence number; appending to
        an unknown run fails. / 追加事件并分配下一次序号；未知运行必须失败。
        """

    def events_after(self, run_id: str, after_seq: int) -> list[ExecutionEvent]: ...

    def mark_waiting(self, run_id: str, payload: dict[str, Any]) -> None:
        """Park an interruptible run awaiting resume. / 挂起可中断的运行等待恢复。"""

    def resume(self, run_id: str, payload: dict[str, Any]) -> None:
        """Move a waiting run back to running; other states are no-ops so
        replayed resumes stay idempotent. / 将 waiting 恢复为 running；其余
        状态幂等无操作。
        """

    def cancel(self, run_id: str, reason: str) -> RunRecord: ...

    def complete(self, run_id: str, output: dict[str, Any]) -> None: ...

    def fail(self, run_id: str, error: AppError) -> None: ...

    def cancelled(self, run_id: str) -> threading.Event:
        """Set once cancellation has been requested; the business handler must
        observe it. / 请求取消后置位，业务处理器必须观察。
        """


class HandoffRunStore(RunStore, Protocol):
    """Explicit projection import after signed, current-authority verification.

    This SPI grants no authority. The lifecycle adapter must verify the actual
    platform handoff and checkpoint before invoking it; conflicts fail closed.
    """

    def adopt_waiting(self, scope: ScopeKey, idempotency_key: str, last_event_seq: int) -> RunRecord: ...


class GenerationRunStore(RunStore, Protocol):
    """Optional SPI for allocating non-secret per-revision event ranges.

    Implementations receive only the already-authorized scope, idempotency key
    and execution revision; bearer or resume tokens are never passed to stores.
    """

    def start_generation(self, scope: ScopeKey, idempotency_key: str,
                         execution_revision: int) -> tuple[RunRecord, bool]: ...

    def resume_generation(self, scope: ScopeKey, idempotency_key: str,
                          execution_revision: int) -> None: ...


class RecoveryGenerationRunStore(GenerationRunStore, Protocol):
    """Explicit projection replacement after platform-signed stop recovery.

    The method receives only non-secret identity and revision facts. It never
    receives a request, bearer, recovery marker, or confirmation token.
    """

    def recover_generation(self, scope: ScopeKey, idempotency_key: str,
                           stopped_revision: int, execution_revision: int) -> RunRecord: ...


class _MemoryRun:
    def __init__(self, record: RunRecord, *, sequence_base: int = 0,
                 generation_revision: int | None = None) -> None:
        # The record is rebuilt on each transition; events grow in a list that
        # snapshots copy, mirroring the Go implementation's immutable views.
        # 记录在每次迁移时重建；事件列表增长时快照复制，与 Go 实现的只读视图一致。
        self.scope = record.scope
        self.idempotency_key = record.idempotency_key
        self.status = record.status
        self.output: dict[str, Any] = {}
        self.error: AppError | None = None
        self.events: list[ExecutionEvent] = []
        self.sequence_base = sequence_base
        self.generation_revision = generation_revision
        self.cancel = threading.Event()
        self.resume_signal = threading.Event()


class MemoryRunStore:
    """Development-only in-memory RunStore. NOT FOR L2/L3 — state dies with
    the process and there is no cross-replica recovery. Production deployments
    must inject a durable scoped store.

    仅限开发环境的内存 RunStore：不可用于 L2/L3 —— 状态随进程消失且无跨副本
    恢复；生产必须注入持久化存储。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[str, _MemoryRun] = {}

    def start_run(self, request: ExecuteRequest) -> tuple[RunRecord, bool]:
        with self._lock:
            run_id = request.scope.run_id
            if not run_id:
                raise InvalidTransitionError("run id is required")
            existing = self._runs.get(run_id)
            if existing is not None:
                if existing.idempotency_key != request.idempotency_key:
                    raise IdempotencyConflictError("run id reused with a different idempotency key")
                return self._snapshot(run_id, existing), False
            run = _MemoryRun(RunRecord(
                run_id=run_id, scope=request.scope,
                idempotency_key=request.idempotency_key, status=RUNNING,
            ))
            self._runs[run_id] = run
            self._append_locked(run, EVENT_ACCEPTED, {"idempotency_key": request.idempotency_key})
            return self._snapshot(run_id, run), True

    def start_generation(self, scope: ScopeKey, idempotency_key: str,
                         execution_revision: int) -> tuple[RunRecord, bool]:
        """Create an accepted projection in the signed revision's sequence range."""
        base, _ = generation_sequence_range(execution_revision)
        if (not scope.run_id or not isinstance(idempotency_key, str)
                or not idempotency_key or len(idempotency_key) > 128):
            raise InvalidTransitionError("verified generation projection required")
        with self._lock:
            run_id = scope.run_id
            existing = self._runs.get(run_id)
            if existing is not None:
                if (existing.idempotency_key != idempotency_key
                        or existing.scope.model_dump(exclude={"trace_id", "authorization_epoch"})
                        != scope.model_dump(exclude={"trace_id", "authorization_epoch"})
                        or existing.generation_revision != execution_revision):
                    raise IdempotencyConflictError("run already has a different generation")
                return self._snapshot(run_id, existing), False
            run = _MemoryRun(RunRecord(
                run_id=run_id, scope=scope,
                idempotency_key=idempotency_key, status=RUNNING,
            ), sequence_base=base, generation_revision=execution_revision)
            self._append_locked(run, EVENT_ACCEPTED, {"idempotency_key": idempotency_key})
            self._runs[run_id] = run
            return self._snapshot(run_id, run), True

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            return self._snapshot(run_id, run)

    def adopt_waiting(self, scope: ScopeKey, idempotency_key: str, last_event_seq: int) -> RunRecord:
        """Import an absent local projection; never fabricate previous events.

        This development store remains ephemeral. The platform SQL/State and
        verified handoff are authoritative, not this import or a waiting flag.
        """
        if (not scope.run_id or not idempotency_key or len(idempotency_key) > 128
                or type(last_event_seq) is not int or not 1 <= last_event_seq < 1 << 53):
            raise InvalidTransitionError("verified resume projection required")
        with self._lock:
            run_id = scope.run_id
            if run_id in self._runs:
                raise IdempotencyConflictError("local projection already exists")
            run = _MemoryRun(RunRecord(run_id=run_id, scope=scope,
                                     idempotency_key=idempotency_key, status=WAITING))
            run.sequence_base = last_event_seq
            self._runs[run_id] = run
            return self._snapshot(run_id, run)

    def resume_generation(self, scope: ScopeKey, idempotency_key: str,
                          execution_revision: int) -> None:
        """Resume a waiting projection at a fresh revision boundary atomically."""
        base, limit = generation_sequence_range(execution_revision)
        if (not scope.run_id or not isinstance(idempotency_key, str)
                or not idempotency_key or len(idempotency_key) > 128):
            raise InvalidTransitionError("verified generation projection required")
        with self._lock:
            run_id = scope.run_id
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if (run.idempotency_key != idempotency_key
                    or run.scope.model_dump(exclude={"trace_id", "authorization_epoch"})
                    != scope.model_dump(exclude={"trace_id", "authorization_epoch"})):
                raise IdempotencyConflictError("run generation scope or idempotency conflict")
            if run.status != WAITING or (run.generation_revision is not None
                                         and execution_revision <= run.generation_revision):
                raise InvalidTransitionError("only a newer generation can resume a waiting run")
            last_sequence = max(run.sequence_base, run.events[-1].seq if run.events else 0)
            if base < last_sequence:
                raise InvalidTransitionError("new generation event range overlaps prior events")
            next_sequence = max(base, last_sequence) + 1
            if next_sequence > limit or next_sequence > MAX_EVENT_SEQUENCE:
                raise InvalidTransitionError("generation event sequence range exhausted")
            # All checks precede mutation, so range exhaustion cannot leave a
            # running status or a moved sequence base without its started event.
            run.sequence_base = base
            run.generation_revision = execution_revision
            run.status = RUNNING
            self._append_locked(run, EVENT_STARTED, {"operation": "resume"})
            run.resume_signal.set()

    def recover_generation(self, scope: ScopeKey, idempotency_key: str,
                           stopped_revision: int, execution_revision: int) -> RunRecord:
        """Replace only a confirmed terminal generation with one fresh projection."""
        if (type(stopped_revision) is not int or stopped_revision < 1
                or type(execution_revision) is not int
                or execution_revision != stopped_revision + 3
                or not scope.run_id or not isinstance(idempotency_key, str)
                or not idempotency_key or len(idempotency_key) > 128):
            raise InvalidTransitionError("verified runtime recovery projection required")
        base, limit = generation_sequence_range(execution_revision)
        if base + 1 > limit:
            raise InvalidTransitionError("generation event sequence range exhausted")
        stable_scope = scope.model_dump(exclude={"trace_id", "authorization_epoch"})
        with self._lock:
            existing = self._runs.get(scope.run_id)
            prior_events: list[ExecutionEvent] = []
            if existing is not None:
                if (existing.idempotency_key != idempotency_key
                        or existing.scope.model_dump(exclude={"trace_id", "authorization_epoch"}) != stable_scope
                        or existing.status not in TERMINAL_STATUSES
                        or type(existing.generation_revision) is not int
                        or existing.generation_revision != stopped_revision):
                    raise IdempotencyConflictError("runtime recovery projection conflict")
                prior_events = list(existing.events)
                last_sequence = prior_events[-1].seq if prior_events else 0
                if prior_events and (type(last_sequence) is not int
                                     or not 1 <= last_sequence <= MAX_EVENT_SEQUENCE):
                    raise InvalidTransitionError("prior event sequence is invalid")
                if base < last_sequence:
                    raise InvalidTransitionError("recovery event range overlaps prior events")

            # Build the replacement off-map so every validation and event
            # allocation succeeds before the old terminal projection changes.
            recovered = _MemoryRun(
                RunRecord(run_id=scope.run_id, scope=scope,
                          idempotency_key=idempotency_key, status=RUNNING),
                sequence_base=base, generation_revision=execution_revision,
            )
            recovered.events = prior_events
            self._append_locked(recovered, EVENT_STARTED,
                                {"operation": "resume", "reason": "runtime_recovery"})
            recovered.resume_signal.set()
            self._runs[scope.run_id] = recovered
            return self._snapshot(scope.run_id, recovered)

    def append_event(self, run_id: str, event_type: str, payload: dict[str, Any]) -> ExecutionEvent:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            return self._append_locked(run, event_type, payload)

    def _append_locked(self, run: _MemoryRun, event_type: str, payload: dict[str, Any]) -> ExecutionEvent:
        next_sequence = max(run.sequence_base, run.events[-1].seq if run.events else 0) + 1
        if next_sequence > self._sequence_limit(run):
            raise InvalidTransitionError("generation event sequence range exhausted")
        event = ExecutionEvent(
            run_id=run.scope.run_id,
            seq=next_sequence,
            event_type=event_type,  # type: ignore[arg-type]
            occurred_at=datetime.now(tz=timezone.utc),
            payload=payload if payload else {},
        )
        run.events.append(event)
        return event

    @staticmethod
    def _sequence_limit(run: _MemoryRun) -> int:
        if run.generation_revision is None:
            return MAX_EVENT_SEQUENCE
        return generation_sequence_range(run.generation_revision)[1]

    def _ensure_event_available(self, run: _MemoryRun) -> None:
        next_sequence = max(run.sequence_base, run.events[-1].seq if run.events else 0) + 1
        if next_sequence > self._sequence_limit(run):
            raise InvalidTransitionError("generation event sequence range exhausted")

    def events_after(self, run_id: str, after_seq: int) -> list[ExecutionEvent]:
        validate_event_cursor(after_seq)
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            return [event for event in run.events if event.seq > after_seq]

    def mark_waiting(self, run_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if run.status != RUNNING:
                raise InvalidTransitionError("only a running run can wait")
            self._ensure_event_available(run)
            run.status = WAITING
            self._append_locked(run, EVENT_WAITING, payload)

    def resume(self, run_id: str, payload: dict[str, Any]) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if run.status != WAITING:
                return
            self._ensure_event_available(run)
            run.status = RUNNING
            self._append_locked(run, EVENT_STARTED, payload)
            # The signal stays set: a handler that parks after the resume must
            # observe it and re-read the state instead of waiting forever.
            # 信号保持置位：恢复之后才挂起的处理器必须能观察到它并重读状态。
            run.resume_signal.set()

    def cancel(self, run_id: str, reason: str) -> RunRecord:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if run.status in TERMINAL_STATUSES:
                return self._snapshot(run_id, run)
            self._ensure_event_available(run)
            run.status = CANCELLED
            payload: dict[str, Any] = {"reason": reason} if reason else {}
            self._append_locked(run, EVENT_CANCELLED, payload)
            run.cancel.set()
            return self._snapshot(run_id, run)

    def complete(self, run_id: str, output: dict[str, Any]) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if run.status in TERMINAL_STATUSES:
                raise InvalidTransitionError("run is already terminal")
            self._ensure_event_available(run)
            run.status = SUCCEEDED
            run.output = dict(output)
            self._append_locked(run, EVENT_COMPLETED, {})

    def fail(self, run_id: str, error: AppError) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            if run.status in TERMINAL_STATUSES:
                raise InvalidTransitionError("run is already terminal")
            self._ensure_event_available(run)
            run.status = FAILED
            run.error = error
            self._append_locked(run, EVENT_FAILED, {"code": error.code})

    def cancelled(self, run_id: str) -> threading.Event:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            return run.cancel

    def resume_signal(self, run_id: str) -> threading.Event:
        """Expose the per-run resume notification for handlers that park on
        interrupt; a development-store affordance.

        暴露每次运行的恢复通知，供中断挂起的业务处理器使用。
        """
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise RunUnknownError(f"run is unknown: {run_id}")
            return run.resume_signal

    def _snapshot(self, run_id: str, run: _MemoryRun) -> RunRecord:
        return RunRecord(
            run_id=run_id, scope=run.scope, idempotency_key=run.idempotency_key,
            status=run.status, output=dict(run.output), error=run.error,
            events=tuple(run.events),
        )
