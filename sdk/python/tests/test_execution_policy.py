import copy

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError


class PolicyClient(CapabilityGatewayClient):
    def __init__(self):
        self.value = {"version": "harness-policy/v2", "policy_hash": "a" * 64,
            "server_time_ms": 123456789, "limits": {"max_rounds": 3, "max_tool_calls": 2,
                "max_repeated_calls": 1, "max_elapsed_seconds": 30, "limit_behavior": "incomplete"},
            "execution": {"task_timeout_seconds": 1800, "batch": {
                "max_items": 1000, "item_timeout_seconds": 30, "elapsed_seconds": 1800},
                "window": {"started_ms": 123456000, "deadline_ms": 125256000}}}
        self.requests = []

    async def _post(self, path, payload, timeout):
        self.requests.append((path, payload))
        return copy.deepcopy(self.value)


@pytest.mark.asyncio
async def test_batch_disclosure_is_explicit_and_accepts_published_large_profile():
    client = PolicyClient()
    result = await client.load_execution_policy()
    assert result["execution"]["batch"]["item_timeout_seconds"] == 30
    assert client.requests == [("/internal/runtime/harness-policy", {"include_batch": True})]
    client.value["execution"]["batch"] = None
    del client.value["execution"]["window"]
    assert (await client.load_execution_policy())["execution"]["batch"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("elapsed_seconds", 300), ("max_items", True),
    ("max_items", 10001), ("item_timeout_seconds", 1801), ("item_timeout_seconds", 0)])
async def test_conflicting_or_unbounded_profiles_fail_before_work_is_admitted(field, value):
    client = PolicyClient()
    client.value["execution"]["batch"][field] = value
    with pytest.raises(GatewayError, match="HARNESS_POLICY_REJECTED"):
        await client.load_execution_policy()
