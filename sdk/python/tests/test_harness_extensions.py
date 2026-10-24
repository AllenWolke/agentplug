import copy
import time

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.harness import EXTENDED_STATE_SCHEMA
from test_public_harness import Fixture, input


def allow(operation, state):
    return operation["name"] == "ticket.update" and operation["payload"] == {"sequence": 9007199254740993}


@pytest.mark.asyncio
async def test_action_guard_blocks_before_tool_dispatch():
    client = Fixture()
    with pytest.raises(GatewayError, match="HARNESS_ACTION_REJECTED"):
        await client.run_harness(input(), key="guard", action_validator=lambda op, view: False, extension_id="guard.v1")
    assert client.models == 1 and client.effects == 0
    assert "/internal/tool/invoke" not in client.paths
    assert client.checkpoint["value"]["version"] == "harness-loop/v2"


@pytest.mark.asyncio
async def test_progress_stops_without_an_extra_model_call_and_replay_is_free():
    client = Fixture()
    def progress(observation, view):
        assert view["tool_count"] == 1 and len(view["observations"]) == 1
        return {"completion_status": "completed", "finish_reason": "evidence_complete"}
    parameters = dict(key="guard", confirmation_token="opaque", action_validator=allow,
                      progress_evaluator=progress, extension_id="guard/v1")
    result = await client.run_harness(input(), **parameters)
    assert result["status"] == "completed"
    assert result["execution"]["decision_count"] == result["execution"]["tool_count"] == 1
    assert client.models == client.effects == 1
    assert await client.run_harness(input(), **parameters) == result
    assert client.models == client.effects == 1


@pytest.mark.asyncio
async def test_progress_after_lost_tool_result_save_uses_receipt_only():
    class LostCompletion(Fixture):
        lost = True
        async def save_checkpoint(self, namespace, key, schema, value, expected, operation_key, **kwargs):
            if self.lost and value["phase"] == "done" and value["tool_count"] == 1:
                self.lost = False
                raise GatewayError("STATE_UNAVAILABLE", "fixed")
            return await super().save_checkpoint(namespace, key, schema, value, expected, operation_key, **kwargs)
    client = LostCompletion()
    parameters = dict(key="guard", confirmation_token="opaque", action_validator=allow,
                      progress_evaluator=lambda op, view: {"completion_status": "completed"}, extension_id="guard.v1")
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await client.run_harness(input(), **parameters)
    result = await client.run_harness(input(), **parameters)
    assert client.effects == client.models == client.queries == 1
    assert result["execution"]["tool_count"] == 1


@pytest.mark.asyncio
async def test_extended_model_receipts_capture_each_stage_and_not_replay():
    client = Fixture()
    parameters = dict(key="guard", confirmation_token="opaque", action_validator=allow, extension_id="guard.v1")
    result = await client.run_harness(input(), **parameters)
    assert result["execution"]["decision_count"] == client.models == 2
    assert len({item["idempotency_key"] for item in result["execution"]["model_receipts"]}) == 2
    assert await client.run_harness(input(), **parameters) == result
    assert client.models == 2


@pytest.mark.asyncio
async def test_semantics_or_deadline_changes_cannot_reuse_extended_checkpoint():
    client = Fixture()
    parameters = dict(key="guard", confirmation_token="opaque", action_validator=allow, extension_id="guard.v1")
    await client.run_harness(input(), **parameters)
    with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
        await client.run_harness(input(), **{**parameters, "extension_id": "guard.v2"})
    with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
        await client.run_harness(input(), **{**parameters, "deadline_ms": int(time.time() * 1000) + 1000})


@pytest.mark.asyncio
async def test_initial_deadline_blocks_context_and_model_dispatch():
    client = Fixture(policy={"limit_behavior": "incomplete"})
    result = await client.run_harness(input(), key="guard", extension_id="guard.v1",
                                      deadline_ms=int(time.time() * 1000) - 100)
    assert result["status"] == "incomplete" and client.models == client.contexts == client.effects == 0


@pytest.mark.asyncio
async def test_extension_requires_version_identifier_and_v1_remains_unchanged():
    client = Fixture()
    with pytest.raises(GatewayError, match="HARNESS_CONFIG_INVALID"):
        await client.run_harness(input(), key="guard", action_validator=allow)
    await client.run_harness(input(), key="legacy", confirmation_token="opaque")
    assert client.checkpoint["value"]["version"] == "harness-loop/v1"
    assert "model_receipts" not in client.checkpoint["value"]
