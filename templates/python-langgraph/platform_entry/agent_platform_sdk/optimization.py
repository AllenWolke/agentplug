"""Bounded orchestration and safe stage measurements, independent of domains.

No credentials, user inputs, outputs, raw exception messages or model tokens
enter measurements. Platform authorization and budget ledgers remain decisive.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
import math
import random
import re
import time
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def authority_failure(error: BaseException) -> bool:
    """Errors that must stop a batch rather than be hidden as degradation."""
    code = str(getattr(error, "code", "")).upper()
    status = getattr(error, "status_code", None)
    return status in {401, 403} or any(part in code for part in (
        "DENIED", "UNAUTHORIZED", "FORBIDDEN", "SIGNATURE", "CONTEXT_INVALID",
        "CONTEXT_EXPIRED", "POLICY_", "AUTHORIZATION_", "WORKLOAD_",
        "CREDENTIAL_", "TOKEN_", "BUDGET_", "RUN_CANCEL", "EXECUTION_STOP",
        "RUN_LEASE", "RUN_RESUME_UNCONFIRMED", "MODEL_SELECTION_MISMATCH",
        "ASSET_VERSION_MISMATCH", "INSTALLATION_REVOKED",
        "TOOL_CONFIRMATION_",
    ))


def decisive_error(error: BaseException) -> BaseException:
    """Preserve any authority failure, even when another sibling failed first."""
    leaves: list[BaseException] = []
    def visit(item: BaseException) -> None:
        if isinstance(item, BaseExceptionGroup):
            for child in item.exceptions:
                visit(child)
        else:
            leaves.append(item)
    visit(error)
    return next((item for item in leaves if authority_failure(item)), leaves[0])


@dataclass
class DeadlineBudget:
    """Local upper bound; it cannot relax the platform's current tree budget."""

    expires_at: float
    maximum_calls: int
    calls: int = 0
    created_at: float = 0

    @classmethod
    def after(cls, seconds: float, maximum_calls: int = 16) -> "DeadlineBudget":
        if not math.isfinite(seconds) or seconds <= 0 or not 1 <= maximum_calls <= 1024:
            raise ValueError("finite deadline and bounded calls required")
        started = time.monotonic()
        return cls(started + seconds, maximum_calls, created_at=started)

    def remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("local operation deadline exceeded")
        return remaining

    def admit_call(self) -> None:
        self.remaining()
        if self.calls >= self.maximum_calls:
            from .capability_client import GatewayError
            raise GatewayError("LOCAL_CALL_BUDGET_EXHAUSTED", "bounded call limit reached")
        self.calls += 1


class StageRecorder:
    """Measurements with process CPU explicitly marked non-additive."""

    def __init__(self, sink: Callable[[dict[str, Any]], None] | None = None):
        self.samples: list[dict[str, Any]] = []
        self.sink = sink

    @contextmanager
    def stage(self, name: str, **counts: int):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("invalid stage label")
        allowed = {"calls", "input_tokens", "output_tokens", "retry_count",
                   "cache_hits", "cache_misses", "queue_depth", "queue_wait_ms", "documents", "chunks"}
        if set(counts) - allowed or any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("invalid stage counters")
        start, cpu = time.monotonic(), time.process_time()
        status, error_type = "succeeded", ""
        try:
            yield counts
        except BaseException as error:
            status = "cancelled" if isinstance(error, asyncio.CancelledError) else "failed"
            error_type = type(error).__name__
            raise
        finally:
            sample = {
                "version": "agent-stage-measurement/v1", "stage": name,
                "wall_ms": (time.monotonic() - start) * 1000,
                "process_cpu_ms": (time.process_time() - cpu) * 1000,
                "cpu_attribution": "process_global_non_additive",
                "status": status, "error_type": error_type, **counts,
            }
            self.samples.append(sample)
            if self.sink is not None:
                try:
                    self.sink(dict(sample))
                except Exception:
                    # An optional telemetry sink must not mask an authorization
                    # failure or change the result of a completed side effect.
                    sample['telemetry_sink_failed'] = True


async def retry_bounded(
    call: Callable[[], Awaitable[R]], *, budget: DeadlineBudget,
    safe_to_retry: Callable[[BaseException], bool], attempts: int = 2,
    random_source: random.Random | None = None, recorder: StageRecorder | None = None,
) -> R:
    """Unknown side effects/charges are never presumed safe to retry.

    The caller must positively classify a read or a verified not-submitted
    receipt. Retry-After is honored only when finite, bounded and within deadline.
    """
    if not 1 <= attempts <= 8:
        raise ValueError("attempt count must be 1..8")
    rng = random_source or random.Random()
    for attempt in range(attempts):
        budget.admit_call()
        try:
            async with asyncio.timeout(budget.remaining()):
                if recorder is None:
                    return await call()
                with recorder.stage("gateway.attempt", calls=1):
                    return await call()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if authority_failure(error) or attempt + 1 == attempts or not safe_to_retry(error):
                raise
            delay = min(0.05 * 2**attempt, 1.0) * rng.uniform(0.5, 1.5)
            retry_after = getattr(error, "retry_after", None)
            if isinstance(retry_after, (int, float)) and math.isfinite(retry_after):
                delay = max(delay, min(max(0.0, retry_after), 30.0))
            if delay >= budget.remaining():
                raise TimeoutError("retry cannot fit operation deadline") from error
            if recorder is None:
                await asyncio.sleep(delay)
            else:
                with recorder.stage("retry.backoff", retry_count=1):
                    await asyncio.sleep(delay)
    raise AssertionError("unreachable retry state")


async def bounded_map(
    values: Iterable[T], handler: Callable[[T, DeadlineBudget], Awaitable[R]], *,
    workers: int = 8, queue_factor: int = 2, item_timeout: float = 30,
    batch_timeout: float = 300, maximum_calls: int = 16,
    recorder: StageRecorder | None = None,
) -> list[R]:
    """A producer and fixed workers; no task is allocated for every item.

    Each item's deadline begins before waiting for queue admission. Batch
    cancellation/authority failure stops producer and all workers and awaits
    their exits before returning. The handler owns safe partial-result storage.
    """
    if not 1 <= workers <= 64 or not 1 <= queue_factor <= 8:
        raise ValueError("invalid bounded worker configuration")
    batch = DeadlineBudget.after(batch_timeout, maximum_calls)
    queue: asyncio.Queue[tuple[int, T, DeadlineBudget] | None] = asyncio.Queue(workers * queue_factor)
    results: list[R | None] = []
    parent = asyncio.current_task()
    aborting = False

    async def produce() -> None:
        for value in values:
            index = len(results)
            results.append(None)
            item = DeadlineBudget.after(item_timeout, maximum_calls)
            item.expires_at = min(item.expires_at, batch.expires_at)
            await queue.put((index, value, item))
        for _ in range(workers):
            await queue.put(None)

    async def consume() -> None:
        nonlocal aborting
        while True:
            work = await queue.get()
            try:
                if work is None:
                    return
                index, value, item = work
                if recorder is None:
                    results[index] = await handler(value, item)
                else:
                    with recorder.stage("queue.worker", queue_depth=queue.qsize(),
                                        queue_wait_ms=int((time.monotonic()-item.created_at)*1000)):
                        results[index] = await handler(value, item)
            except asyncio.CancelledError:
                if parent is not None and not aborting and parent.cancelling() == 0:
                    parent.cancel()
                raise
            except Exception:
                aborting = True
                raise
            finally:
                queue.task_done()

    try:
        async with asyncio.timeout(batch.remaining()):
            async with asyncio.TaskGroup() as group:
                group.create_task(produce())
                for _ in range(workers):
                    group.create_task(consume())
    except ExceptionGroup as errors:
        # Keep public authorization error codes intact, not an opaque group.
        raise decisive_error(errors) from errors
    if any(value is None for value in results):
        raise RuntimeError("bounded worker left an uncollected result")
    return list(results)  # type: ignore[return-value]
