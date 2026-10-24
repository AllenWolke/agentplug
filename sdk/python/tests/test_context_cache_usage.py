"""Measured cache tokens survive both public SDK paths used by the two Agents."""
from types import SimpleNamespace
import time

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.durable_stage import DurableStageClient
from agent_platform_sdk.model_usage import chat_usage


@pytest.mark.parametrize("value", [
    {"input_tokens": 10, "output_tokens": 2, "cached_input_tokens": -1, "uncached_input_tokens": 11},
    {"input_tokens": 10, "cached_input_tokens": 5},
    {"input_tokens": 10, "cached_input_tokens": True, "uncached_input_tokens": 9},
    {"input_tokens": 10, "cached_input_tokens": 6, "uncached_input_tokens": 5},
])
def test_invalid_measured_split_cannot_become_usage(value):
    with pytest.raises(GatewayError, match="MODEL_USAGE_INVALID"):
        chat_usage(value)


def test_cache_usage_unknown_is_distinct_from_measured_zero():
    assert chat_usage({}) == {"prompt_tokens": None, "completion_tokens": None}
    assert "cached_input_tokens" not in chat_usage({"input_tokens": 10, "output_tokens": 2})
    assert chat_usage({"input_tokens": 10, "cached_input_tokens": 0, "uncached_input_tokens": 10})["cached_input_tokens"] == 0


@pytest.mark.asyncio
async def test_common_chat_and_durable_stages_preserve_cache_billing_receipt():
    receipt = {"text": "fresh answer", "model": "approved", "usage": {
        "input_tokens": 1000, "output_tokens": 10, "cached_input_tokens": 750, "uncached_input_tokens": 250},
        "context_cache": {"version": "context-prefix/v1", "mode": "provider_prefix"},
        "billing": {"currency": "USD", "cost_micros": 183, "cache_savings_micros": 225}}

    class Fixture(CapabilityGatewayClient):
        def __init__(self): self._context = SimpleNamespace(prompt_template_hash="hash", task_id="run")
        async def _post(self, path, payload, timeout): return receipt
        async def run_harness(self, *args, **kwargs):
            return {"status": "completed", "output": receipt, "execution": {"model_calls": 1}}

    client = Fixture()
    normal = await client.chat([{"role": "user", "content": "question"}])
    durable = await DurableStageClient(client, key="stage", deadline_ms=int(time.time()*1000)+30000).chat([
        {"role": "user", "content": "question"}])
    for value in (normal, durable):
        assert value["usage"]["prompt_tokens"] == 1000
        assert value["usage"]["cached_input_tokens"] == 750
        assert value["usage"]["uncached_input_tokens"] == 250
        assert value["context_cache"] == receipt["context_cache"]
        assert value["billing"] == receipt["billing"]
