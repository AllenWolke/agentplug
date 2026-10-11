from __future__ import annotations

import pytest

from agent_platform_sdk.run_gateway import RunGateway


class FakeProvider:
    async def start(self, work):
        self.work = work

    async def close(self):
        self.closed = True

    async def ready(self):
        return True

    async def enqueue(self, run_id, payload):
        self.enqueued = (run_id, payload)
        return True

    async def publish(self, run_id, event_type, payload=None):
        return 1

    async def cancel(self, run_id):
        return run_id == "run-a"

    async def resume(self, run_id, resume_input):
        return run_id == "run-a"

    async def scope_matches(self, run_id, scope):
        return run_id == scope["run_id"]

    async def stream(self, run_id, after_seq=0):
        yield {"seq": after_seq + 1, "type": "task_completed", "payload": {}}


@pytest.mark.asyncio
async def test_run_gateway_delegates_lifecycle_and_scope() -> None:
    provider = FakeProvider()
    gateway = RunGateway(provider)
    await gateway.start(lambda _: None)
    assert await gateway.ready() is True
    assert await gateway.enqueue("run-a", {"x": 1}) is True
    assert await gateway.publish("run-a", "started", {}) == 1
    assert await gateway.scope_matches("run-a", {"run_id": "run-a"}) is True
    assert await gateway.cancel("run-a") is True
    assert await gateway.resume("run-a", {}) is True
    assert [event async for event in gateway.stream("run-a")] == [
        {"seq": 1, "type": "task_completed", "payload": {}}
    ]
    await gateway.close()
    assert provider.closed is True
