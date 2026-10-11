import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError


@pytest.mark.asyncio
async def test_confirmation_preserves_approved_call_and_does_not_retry_unknown(monkeypatch):
    client = object.__new__(CapabilityGatewayClient)
    calls = []

    async def post(path, payload, timeout):
        calls.append((path, payload))
        raise GatewayError("TOOL_RESULT_UNKNOWN", "reconciliation required")

    monkeypatch.setattr(client, "_post", post)
    with pytest.raises(ValueError):
        await client.invoke_tool("clock.now", {}, confirmation_token="opaque-approval")
    assert not calls
    with pytest.raises(GatewayError) as error:
        await client.invoke_tool("clock.now", {}, call_id="approved-call", confirmation_token="opaque-approval")
    assert error.value.code == "TOOL_RESULT_UNKNOWN"
    assert len(calls) == 1
    assert calls[0][0] == "/internal/tool/invoke"
    assert calls[0][1]["call_id"] == "approved-call"
    assert calls[0][1]["confirmation_token"] == "opaque-approval"
    assert calls[0][1]["confirmed"] is False
