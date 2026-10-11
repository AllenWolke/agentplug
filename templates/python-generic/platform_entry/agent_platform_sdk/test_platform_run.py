from __future__ import annotations

import pytest

from agent_platform_sdk.platform_run import PlatformProjectionProvider


class LocalProvider:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self.jobs: set[str] = set()

    async def start(self, work):
        self.work = work

    async def close(self):
        self.closed = True

    async def ready(self):
        return True

    async def enqueue(self, run_id, payload):
        self.jobs.add(run_id)
        return True

    async def publish(self, run_id, event_type, payload=None):
        self.events.append({"type": event_type, "payload": payload or {}})
        return len(self.events)

    async def cancel(self, run_id):
        return run_id in self.jobs

    async def resume(self, run_id, resume_input):
        return run_id in self.jobs

    async def scope_matches(self, run_id, scope):
        return run_id in self.jobs

    async def stream(self, run_id, after_seq=0):
        for event in self.events[after_seq:]:
            yield event


class PlatformFake:
    def __init__(self) -> None:
        self.runs = {}
        self.events_by_run = {}

    async def create(self, payload):
        run_id = payload["run_id"]
        existing = self.runs.get(run_id)
        if existing:
            assert existing["fingerprint"] == payload["fingerprint"]
            return existing
        record = {
            "run_id": run_id,
            "status": "accepted",
            "revision": 1,
            "scope": payload["scope"],
            "fingerprint": payload["fingerprint"],
        }
        self.runs[run_id] = record
        self.events_by_run[run_id] = [{"seq": 1, "event_type": "accepted", "payload": {}}]
        return record

    async def get(self, run_id, scope):
        return self.runs[run_id]

    async def transition(self, run_id, scope, from_status, to_status, revision):
        record = self.runs[run_id]
        assert record["status"] == from_status
        assert record["revision"] == revision
        record["status"] = to_status
        record["revision"] += 1
        self.events_by_run[run_id].append(
            {
                "seq": len(self.events_by_run[run_id]) + 1,
                "event_type": "status",
                "payload": {
                    "from": from_status,
                    "to": to_status,
                    "revision": record["revision"],
                },
            }
        )
        return record

    async def append_event(self, run_id, scope, event_type, payload):
        events = self.events_by_run[run_id]
        event = {"seq": len(events) + 1, "event_type": event_type, "payload": payload}
        events.append(event)
        return event

    async def events(self, run_id, scope, after_seq):
        return [item for item in self.events_by_run[run_id] if item["seq"] > after_seq]

    async def ready(self):
        return True


def scope(run_id: str) -> dict:
    return {
        "tenant_id": "tenant",
        "department_id": "dept",
        "application_id": "app",
        "agent_instance_id": "instance",
        "installation_id": "installation",
        "agent_id": "agent",
        "agent_version_id": "v1",
        "principal_type": "service_principal",
        "principal_id": "machine",
        "session_id": "session",
        "run_id": run_id,
        "authorization_epoch": 1,
        "trace_id": "0" * 32,
    }


@pytest.mark.asyncio
async def test_projection_provider_creates_scope_bound_platform_run_and_streams() -> None:
    local = LocalProvider()
    platform = PlatformFake()
    provider = PlatformProjectionProvider(local, platform, poll_interval=0.001)
    await provider.start(lambda _: None)
    run_scope = scope("run-1")
    payload = {"request": {"scope": run_scope, "idempotency_key": "idem-1234"}}
    assert await provider.enqueue("run-1", payload) is True
    assert await provider.scope_matches("run-1", run_scope) is True
    assert await provider.publish("run-1", "started", {"stage": "precheck"}) == 3
    assert await provider.publish("run-1", "completed", {}) == 5
    assert platform.runs["run-1"]["status"] == "succeeded"
    events = [item async for item in provider.stream("run-1", after_seq=1)]
    assert events == [
        {"seq": 2, "type": "status", "payload": {"from": "accepted", "to": "running", "revision": 2}},
        {"seq": 3, "type": "started", "payload": {"stage": "precheck"}},
        {"seq": 4, "type": "status", "payload": {"from": "running", "to": "succeeded", "revision": 3}},
        {"seq": 5, "type": "completed", "payload": {}},
    ]
    assert await provider.cancel("run-1") is False
    await provider.close()
    assert local.closed is True


@pytest.mark.asyncio
async def test_projection_provider_rejects_run_scope_mismatch() -> None:
    provider = PlatformProjectionProvider(LocalProvider(), PlatformFake())
    with pytest.raises(ValueError):
        await provider.enqueue("run-1", {"request": {"scope": scope("other")}})
