"""Local scheduler bounds and cancellation, not service-performance evidence."""
import asyncio

import pytest

from agent_platform_sdk.io_limits import shared_io_limit
from agent_platform_sdk.capability_io import LimitedCapabilityClient


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [100, 1000])
async def test_runs_share_global_capacity_without_serializing_independent_runs(count):
    active = {"a": 0, "b": 0}
    peaks = dict(active)
    total_peak = 0
    occupied, release = asyncio.Event(), asyncio.Event()
    limits = {key: shared_io_limit("grouped-scale", "read", 2,
        run_key=key, process_maximum=4) for key in active}

    async def worker(key):
        nonlocal total_peak
        for _ in range(count):
            async with limits[key]:
                active[key] += 1
                peaks[key] = max(peaks[key], active[key])
                total_peak = max(total_peak, sum(active.values()))
                if sum(active.values()) == 4:
                    occupied.set()
                try:
                    await release.wait()
                    await asyncio.sleep(0)
                finally:
                    active[key] -= 1
    tasks = [asyncio.create_task(worker(key)) for key in active for _ in range(3)]
    try:
        await asyncio.wait_for(occupied.wait(), 2)
        assert active == {"a": 2, "b": 2}
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks), 10)
    finally:
        release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert peaks == {"a": 2, "b": 2} and total_peak == 4
    assert active == {"a": 0, "b": 0}
    assert not limits["a"].pool.runs and not limits["a"].pool.holders


@pytest.mark.asyncio
async def test_round_robin_admits_late_run_before_first_run_drains():
    first = shared_io_limit("fair", "model", 1, run_key="a", process_maximum=1)
    second = shared_io_limit("fair", "model", 1, run_key="b", process_maximum=1)
    order = []
    async def wait(label, limiter):
        async with limiter:
            order.append(label)
            await asyncio.sleep(0)
    async with first:
        tasks = [asyncio.create_task(wait(f"a{i}", first)) for i in range(5)]
        await asyncio.sleep(0)
        tasks.append(asyncio.create_task(wait("b", second)))
        await asyncio.sleep(0)
    await asyncio.wait_for(asyncio.gather(*tasks), 2)
    assert order.index("b") <= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("after_grant", [False, True])
async def test_cancelled_waiter_returns_capacity_even_between_grant_and_resume(after_grant):
    limit = shared_io_limit("cancel", "model", 1, run_key="a", process_maximum=1)
    entered = False
    async def waiter():
        nonlocal entered
        async with limit:
            entered = True
    await limit.__aenter__()
    task = asyncio.create_task(waiter())
    await asyncio.sleep(0)
    if after_grant:
        # Release synchronously grants the queued Future; cancel before the
        # waiter resumes, exercising the permit handoff rather than a sleep.
        await limit.__aexit__(None, None, None)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    if not after_grant:
        await limit.__aexit__(None, None, None)
    assert not entered
    async with asyncio.timeout(1):
        async with limit:
            assert limit.pool.active == 1
    assert limit.pool.active == 0 and not limit.pool.runs


@pytest.mark.asyncio
async def test_conflicting_configuration_and_nested_acquisition_fail_without_leaking():
    limit = shared_io_limit("config", "read", 1, run_key="a", process_maximum=2)
    with pytest.raises(ValueError):
        shared_io_limit("config", "read", 1, run_key="b", process_maximum=3)
    async with limit:
        with pytest.raises(RuntimeError, match="nested"):
            async with limit:
                pass
    assert not limit.pool.runs and not limit.pool.holders


@pytest.mark.asyncio
async def test_rpc_deadline_includes_wait_and_never_sends_after_capacity_timeout():
    class Transport:
        _context = object()
        calls = 0
        async def _post(self, *args):
            self.calls += 1
            return {}
    transport = Transport()
    client = LimitedCapabilityClient.for_run(transport, "rpc-deadline", "a",
        {"/internal/model/generate": ("model", 1, 1)})
    blocker = shared_io_limit("rpc-deadline", "model", 1, run_key="other", process_maximum=1)
    held, release = asyncio.Event(), asyncio.Event()
    async def occupy():
        async with blocker:
            held.set()
            await release.wait()
    holder = asyncio.create_task(occupy())
    try:
        await asyncio.wait_for(held.wait(), 1)
        with pytest.raises(TimeoutError):
            await client._post("/internal/model/generate", {}, .02)
    finally:
        release.set()
        await asyncio.wait_for(holder, 1)
    assert transport.calls == 0
    await client._post("/internal/model/generate", {}, 1)
    assert transport.calls == 1
