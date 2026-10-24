"""Only explicit in-progress receipts allow bounded, authorization-aware polling."""

import asyncio
import json

import httpx
import pytest

from agent_platform_sdk import tool_client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "codes, expected_calls",
    [
        (["TOOL_INVOCATION_IN_PROGRESS", "TOOL_INVOCATION_IN_PROGRESS", None], 3),
        (["TOOL_INVOCATION_IN_PROGRESS"] * 5, 5),
        (["TOOL_INVOCATION_IN_PROGRESS", "CAPABILITY_DENIED"], 2),
        (["ISSUE_COMMAND_REJECTED"], 1),
        (["IDEMPOTENCY_CONFLICT"], 1),
    ],
)
async def test_receipt_polling_reuses_key_and_revalidates(monkeypatch, codes, expected_calls):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("PLATFORM_CAPABILITY_URL", "http://fixture")
    requests = []
    renewals = []
    delays = []

    async def renew(context, base, token):
        renewals.append(base)

    async def sleep(delay):
        delays.append(delay)

    def handle(request):
        requests.append(json.loads(request.content))
        code = codes[len(requests) - 1]
        if code is None:
            return httpx.Response(200, json={"data": {"data": {"receipt": "committed"}}})
        return httpx.Response(403 if code == "CAPABILITY_DENIED" else 409,
                              json={"code": code, "message": "private-upstream-message"})

    real_client = httpx.AsyncClient
    # The governed tool client passes its own connection transport; the fixture
    # replaces that transport with the mock instead of adding a second one.
    monkeypatch.setattr(tool_client.httpx, "AsyncClient",
                        lambda **options: real_client(**{**options, "transport": httpx.MockTransport(handle)}))
    monkeypatch.setattr(tool_client, "renew_context_token", renew)
    monkeypatch.setattr(tool_client.asyncio, "sleep", sleep)
    if codes[-1] is None:
        assert await tool_client.invoke_tool("get_lineage", {"field": "shared"}, {}, "fixture-token") == {"receipt": "committed"}
    else:
        with pytest.raises(tool_client.ToolGatewayError) as error:
            await tool_client.invoke_tool("get_lineage", {"field": "shared"}, {}, "fixture-token")
        assert error.value.code == codes[-1]
    assert len(requests) == len(renewals) == expected_calls
    assert len({request["input"]["call_id"] for request in requests}) == 1
    assert delays == [0.05 * 2**index for index in range(expected_calls - 1)]


@pytest.mark.asyncio
async def test_cancelled_polling_stops_before_next_request(monkeypatch):
    calls = []

    async def invoke(*args):
        calls.append(True)
        raise tool_client.ToolGatewayError("TOOL_INVOCATION_IN_PROGRESS", "fixed")

    async def cancelled(delay):
        raise asyncio.CancelledError()

    monkeypatch.setattr(tool_client, "_invoke_tool_once", invoke)
    monkeypatch.setattr(tool_client.asyncio, "sleep", cancelled)
    with pytest.raises(asyncio.CancelledError):
        await tool_client.invoke_tool("get_lineage", {}, {}, "fixture-token")
    assert len(calls) == 1
