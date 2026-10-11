import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

import agent_platform_sdk.versioned_index as indexes


@pytest.mark.asyncio
async def test_index_scope_and_permission_versions_expire_independently(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(indexes, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    identity = indexes.IndexIdentity("corpus-1", "model-1", "tokenizer-1", "chunks-1")
    cache = indexes.PermissionScopedSingleflight(maximum=2, ttl_seconds=60)
    calls = 0

    async def check():
        return None

    async def load():
        nonlocal calls
        calls += 1
        return str(calls).encode()

    async def get(selected=identity, actor="tenant-a/user-a", permission="p1", query="q1"):
        return await cache.get(identity=selected, scope_identity=actor, permission_revision=permission,
                               query=query, load=load, check_current=check)

    assert await get() == await get() == b"1"
    for field in ("corpus_revision", "model_revision", "tokenizer_revision", "chunk_configuration"):
        before = calls
        await get(replace(identity, **{field: "changed"}))
        assert calls == before + 1
    await get(actor="tenant-b/user-a")
    await get(permission="p2")
    await get(query="q2")
    assert calls == 8 and len(cache.cache) == 2
    assert await get(query="q2") == b"8"
    clock[0] += 61
    assert await get(query="q2") == b"9"
    assert len(cache.cache) <= 2


@pytest.mark.asyncio
async def test_singleflight_rejects_excess_work_without_starting_another_loader():
    cache = indexes.PermissionScopedSingleflight(maximum=1)
    identity = indexes.IndexIdentity("c", "m", "t", "s")
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def check():
        return None

    async def load():
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return b"authorized"

    def get(query):
        return cache.get(identity=identity, scope_identity="actor", permission_revision="p1",
                         query=query, load=load, check_current=check)

    owner = asyncio.create_task(get("first"))
    await entered.wait()
    try:
        with pytest.raises(RuntimeError, match="SINGLEFLIGHT_CAPACITY_REACHED"):
            await get("second")
        assert calls == 1 and len(cache.inflight) == 1
    finally:
        release.set()
    assert await owner == b"authorized" and not cache.inflight


@pytest.mark.asyncio
async def test_cancelled_owner_fails_followers_without_caching_or_replay():
    cache = indexes.PermissionScopedSingleflight()
    identity = indexes.IndexIdentity("c", "m", "t", "s")
    entered = asyncio.Event()
    calls = 0

    async def check():
        return None

    async def load():
        nonlocal calls
        calls += 1
        entered.set()
        await asyncio.Event().wait()

    def get():
        return cache.get(identity=identity, scope_identity="actor", permission_revision="p1",
                         query="q", load=load, check_current=check)

    owner = asyncio.create_task(get())
    await entered.wait()
    follower = asyncio.create_task(get())
    await asyncio.sleep(0)
    owner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await owner
    with pytest.raises(asyncio.CancelledError):
        await follower
    assert calls == 1 and not cache.cache and not cache.inflight
