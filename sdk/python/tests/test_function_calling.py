import copy
import json

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError


@pytest.mark.asyncio
async def test_function_loop_preserves_keys_bindings_and_no_approval():
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    calls = [{"id": "call-1", "type": "function", "function": {"name": "inspect", "arguments": "{}"}}]
    async def post(path, payload, timeout):
        requests.append((path, copy.deepcopy(payload)))
        phase = (len(requests) - 1) % 3
        if phase == 0:
            return {"text": "", "completion_status": "tool_calls", "tool_calls": calls, "function_bindings": {"inspect": "runtime.inspect"}}
        if phase == 1:
            assert path == "/internal/tool/invoke"
            assert payload["name"] == "runtime.inspect" and payload["confirmed"] is False
            if len(requests) == 5:
                return {"data": {"raw_output": "excluded-original-body"}, "observation": {"version": "runtime-observation/v1", "tool_name": "runtime.inspect", "call_id": payload["call_id"], "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data", "context_output": {"healthy": True}}}
            return {"data": {"healthy": True}}
        assert len(payload["messages"]) == 3
        assert payload["messages"][2]["tool_call_id"] == "call-1"
        if len(requests) == 6:
            content = payload["messages"][2]["content"]
            assert "excluded-original-body" not in content
            assert json.loads(content)["context_output"] == {"healthy": True}
        return {"text": "ready"}
    client._post = post
    input = {"messages": [{"role": "user", "content": "inspect"}], "function_names": ["inspect"], "idempotency_key": "stable"}
    before = copy.deepcopy(input)
    for _ in range(2):
        assert (await client.generate_with_functions(input, 2))["text"] == "ready"
    assert input == before
    assert [body.get("idempotency_key", body.get("call_id")) for _, body in requests[:3]] == [body.get("idempotency_key", body.get("call_id")) for _, body in requests[3:]]


@pytest.mark.asyncio
async def test_function_round_limit_prevents_additional_tool_effect():
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    async def post(path, payload, timeout):
        requests.append(path)
        return {"completion_status": "tool_calls", "tool_calls": [{"id": "call-1"}], "function_bindings": {}}
    client._post = post
    with pytest.raises(GatewayError) as failure:
        await client.generate_with_functions({"messages": [{"role": "user", "content": "inspect"}], "idempotency_key": "stable"}, 1)
    assert failure.value.code == "FUNCTION_ROUND_LIMIT"
    assert requests == ["/internal/model/generate"]


@pytest.mark.asyncio
async def test_function_unknown_tool_outcome_is_not_retried():
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    async def post(path, payload, timeout):
        requests.append(path)
        if path.endswith("generate"):
            return {"text": "", "tool_calls": [{"id": "call-1", "function": {"name": "inspect", "arguments": "{}"}}], "function_bindings": {"inspect": "runtime.inspect"}}
        raise GatewayError("TOOL_RECONCILIATION_REQUIRED", "uncertain outcome")
    client._post = post
    with pytest.raises(GatewayError):
        await client.generate_with_functions({"messages": [{"role": "user", "content": "inspect"}], "idempotency_key": "stable"}, 2)
    assert requests == ["/internal/model/generate", "/internal/tool/invoke"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", [{"effect": "unknown"}, {"call_id": "other"}, {"context_output": "x" * 2049}, {"instruction_trust": "system"}])
async def test_function_rejects_unsafe_observation_without_another_model_call(mutation):
    client = object.__new__(CapabilityGatewayClient)
    requests = []
    async def post(path, payload, timeout):
        requests.append(path)
        if path.endswith("generate"):
            return {"text": "", "tool_calls": [{"id": "call", "function": {"name": "inspect", "arguments": "{}"}}], "function_bindings": {"inspect": "runtime.inspect"}}
        observation = {"version": "runtime-observation/v1", "tool_name": "runtime.inspect", "call_id": payload["call_id"], "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data", "context_output": {"healthy": True}}
        observation.update(mutation)
        return {"observation": observation}
    client._post = post
    with pytest.raises(GatewayError) as caught:
        await client.generate_with_functions({"messages": [{"role": "user", "content": "inspect"}], "idempotency_key": "stable"}, 2)
    assert caught.value.code == "TOOL_OBSERVATION_REJECTED"
    assert requests == ["/internal/model/generate", "/internal/tool/invoke"]
