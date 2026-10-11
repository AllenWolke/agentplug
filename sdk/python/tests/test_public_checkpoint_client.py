import copy

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError


@pytest.mark.asyncio
async def test_checkpoint_keeps_cas_identity_precision_and_conflict_without_retry():
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    async def post(path, payload, timeout):
        requests.append((path, copy.deepcopy(payload)))
        if payload.get("expected_revision") == 1:
            raise GatewayError("STATE_REVISION_CONFLICT", "CAS conflict")
        return {"checkpoint": {"revision": 1, "value": {"sequence": 9007199254740993}}}
    client._post = post
    value = {"sequence": 9007199254740993}
    saved = await client.save_checkpoint("harness", "loop", "schema://state/v1", value, 0, "stable")
    loaded = await client.load_checkpoint("harness", "loop", "schema://state/v1")
    assert saved == loaded and loaded["checkpoint"]["value"] == value
    with pytest.raises(GatewayError) as failure:
        await client.save_checkpoint("harness", "loop", "schema://state/v1", value, 1, "next")
    assert failure.value.code == "STATE_REVISION_CONFLICT"
    assert len(requests) == 3
    assert all(path == "/internal/state/checkpoint" for path, _ in requests)
    assert requests[0][1]["idempotency_key"] == "stable"
    assert value == {"sequence": 9007199254740993}


@pytest.mark.asyncio
async def test_context_preparation_denial_does_not_invoke_model_or_retry():
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    async def post(path, payload, timeout):
        requests.append((path, payload))
        raise GatewayError("CAPABILITY_DENIED", "current model resource denied")
    client._post = post
    with pytest.raises(GatewayError):
        await client.prepare_context([{"role": "user", "content": "question"}], ["inspect"])
    assert requests == [("/internal/context/prepare", {"messages": [{"role": "user", "content": "question"}], "function_names": ["inspect"]})]


@pytest.mark.asyncio
async def test_checkpoint_rejects_ambiguous_revision_before_transport():
    client = object.__new__(CapabilityGatewayClient)
    for revision in (True, -1, 65, 1.5):
        with pytest.raises(ValueError):
            await client.load_checkpoint("harness", "loop", "schema://state/v1", revision)
    for revision in (False, -1, 64):
        with pytest.raises(ValueError):
            await client.save_checkpoint("harness", "loop", "schema://state/v1", {}, revision, "stable")
