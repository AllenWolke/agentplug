"""MemoryRunStore state-machine tests: idempotency, transitions, cancellation,
and per-run event sequence numbering.

MemoryRunStore 状态机测试：幂等、迁移、取消与逐运行事件次序号。
"""

from __future__ import annotations

import pytest

from agent_platform_sdk import (
    IdempotencyConflictError,
    InvalidTransitionError,
    MemoryRunStore,
    RunUnknownError,
)
from agent_platform_sdk.models import AppError, ExecuteRequest


def request(run_id: str = "run-1", idempotency: str = "idem-key-1") -> ExecuteRequest:
    return ExecuteRequest.model_validate({
        "protocol_version": "agent-execution/v2", "context_token": "x" * 32,
        "scope": {"tenant_id": "t", "department_id": "d", "application_id": "a",
            "agent_instance_id": "i", "installation_id": "installation-i", "agent_id": "agent", "agent_version_id": "v1",
            "principal_type": "user", "principal_id": "u", "session_id": "s",
            "run_id": run_id, "authorization_epoch": 1, "trace_id": "a" * 32},
        "operation": "run", "idempotency_key": idempotency, "input_schema": "schema://x/v1",
        "input": {},
    })


def test_start_run_is_idempotent_and_conflicts_on_key_drift() -> None:
    store = MemoryRunStore()
    record, created = store.start_run(request())
    assert created and record.status == "running"
    replay, created_again = store.start_run(request())
    assert not created_again and replay.idempotency_key == "idem-key-1"
    with pytest.raises(IdempotencyConflictError):
        store.start_run(request(idempotency="idem-key-2"))


def test_lifecycle_transitions_and_terminal_protection() -> None:
    store = MemoryRunStore()
    store.start_run(request())
    store.append_event("run-1", "progress", {"stage": "one"})
    store.mark_waiting("run-1", {"reason": "interrupted"})
    assert store.get_run("run-1").status == "waiting"
    store.resume("run-1", {"answer": 42})
    assert store.get_run("run-1").status == "running"
    # Replayed resumes are no-ops. / 重放的 resume 是幂等无操作。
    store.resume("run-1", {})
    store.complete("run-1", {"done": True})
    record = store.get_run("run-1")
    assert record.status == "succeeded" and record.output == {"done": True}
    with pytest.raises(InvalidTransitionError):
        store.complete("run-1", {"again": True})
    with pytest.raises(InvalidTransitionError):
        store.fail("run-1", AppError(code="INTERNAL", message="late failure", retryable=True))


def test_cancel_is_idempotent_and_closes_the_cancelled_event() -> None:
    store = MemoryRunStore()
    store.start_run(request())
    cancelled = store.cancelled("run-1")
    assert not cancelled.is_set()
    record = store.cancel("run-1", "user asked")
    assert record.status == "cancelled"
    assert cancelled.is_set()
    # A second cancel observes the terminal record instead of failing.
    # 二次取消观察到终态记录而非失败。
    assert store.cancel("run-1", "").status == "cancelled"
    # Cancelling a terminal run does not resurrect it for completion.
    # 取消终态运行后不可再完成。
    with pytest.raises(InvalidTransitionError):
        store.complete("run-1", {})


def test_events_use_strictly_increasing_per_run_sequences() -> None:
    store = MemoryRunStore()
    store.start_run(request())
    first = store.append_event("run-1", "progress", {"n": 1})
    second = store.append_event("run-1", "progress", {"n": 2})
    assert first.seq == 2 and second.seq == 3  # accepted occupied seq 1
    assert [e.seq for e in store.events_after("run-1", 2)] == [3]
    with pytest.raises(RunUnknownError):
        store.events_after("missing", 0)


def test_resume_on_cancelled_run_is_a_noop() -> None:
    store = MemoryRunStore()
    store.start_run(request())
    store.cancel("run-1", "gone")
    store.resume("run-1", {})
    assert store.get_run("run-1").status == "cancelled"
