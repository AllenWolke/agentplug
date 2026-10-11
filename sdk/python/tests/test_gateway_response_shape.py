"""Actual SDK clients reject non-object errors / 真实 SDK 拒绝错误响应形状漂移。"""

import httpx
import json
import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.capability_client import MAX_GATEWAY_RESPONSE_BYTES
from agent_platform_sdk import tool_client
from agent_platform_sdk.errors import classify_execution_error


@pytest.mark.asyncio
async def test_capability_unknown_tool_observation_cannot_become_retryable_failure(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    transport = httpx.MockTransport(lambda request: httpx.Response(502, json={"error_code": "TOOL_PROVIDER_FAILED", "message": "private-upstream-body", "data": {"observation": {"version": "runtime-observation/v1", "effect": "unknown"}}}))
    client = CapabilityGatewayClient({}, "http://fixture", "fixture-test-token", transport)
    with pytest.raises(GatewayError) as caught:
        await client._post("/internal/tool/invoke", {"name": "runtime.inspect"}, 10)
    status, error = classify_execution_error(caught.value)
    assert (status, error.code, error.retryable) == (409, "TOOL_RESULT_UNKNOWN", False)
    assert "private-upstream-body" not in error.message


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], None, "private-upstream-body", 503])
async def test_capability_error_response_shape_is_safe(monkeypatch, body):
    monkeypatch.setenv("APP_ENV", "development")
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            503, content=json.dumps(body), headers={"content-type": "application/json"}
        )
    )
    client = CapabilityGatewayClient(
        {}, "http://fixture", "fixture-test-token", transport
    )
    with pytest.raises(GatewayError) as caught:
        await client._post("/internal/knowledge/search", {}, 1)
    status, error = classify_execution_error(caught.value)
    assert (status, error.code, error.retryable) == (
        502,
        "UPSTREAM_PROTOCOL_ERROR",
        False,
    )
    assert "private-upstream-body" not in error.message


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], None, "private-upstream-body", 503])
async def test_tool_error_response_shape_is_safe(monkeypatch, body):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("PLATFORM_CAPABILITY_URL", "http://fixture")
    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            503, content=json.dumps(body), headers={"content-type": "application/json"}
        )
    )
    monkeypatch.setattr(
        tool_client.httpx,
        "AsyncClient",
        lambda **options: real_client(**options, transport=transport),
    )
    with pytest.raises(tool_client.ToolGatewayError) as caught:
        await tool_client.invoke_tool(
            "runtime.inspect", {"verbose": True}, {}, "fixture-test-token"
        )
    status, error = classify_execution_error(caught.value)
    assert (status, error.code, error.retryable) == (
        502,
        "UPSTREAM_PROTOCOL_ERROR",
        False,
    )
    assert "private-upstream-body" not in error.message


@pytest.mark.asyncio
async def test_stop_revision_conflict_retains_only_allowlisted_details(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    control = {
        "version": "agent-child-stop-control-conflict/v1",
        "status": "running",
        "execution_revision": 7,
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(409, json={
        "code": 1, "error_code": "AGENT_STOP_REVISION_CONFLICT",
        "message": "static conflict", "data": {"stop_control": control},
    }))
    client = CapabilityGatewayClient({}, "http://fixture", "fixture-test-token", transport)
    with pytest.raises(GatewayError) as caught:
        await client._post("/internal/agent/cancel", {}, 1)
    expected = {"stop_control": control}
    assert caught.value.details == expected
    status, app_error = classify_execution_error(caught.value)
    assert status == 409 and app_error.code == "AGENT_STOP_REVISION_CONFLICT"
    assert app_error.retryable is False and app_error.details == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("code,status,control", [
    ("AGENT_STOP_REVISION_CONFLICT", 403, {"version": "agent-child-stop-control-conflict/v1", "status": "running", "execution_revision": 7}),
    ("AGENT_ROUTE_CONFLICT", 409, {"version": "agent-child-stop-control-conflict/v1", "status": "running", "execution_revision": 7}),
    ("AGENT_STOP_REVISION_CONFLICT", 409, {"version": "other/v1", "status": "running", "execution_revision": 7}),
    ("AGENT_STOP_REVISION_CONFLICT", 409, {"version": "agent-child-stop-control-conflict/v1", "status": "terminal", "execution_revision": 7}),
    ("AGENT_STOP_REVISION_CONFLICT", 409, {"version": "agent-child-stop-control-conflict/v1", "status": "running", "execution_revision": True}),
    ("AGENT_STOP_REVISION_CONFLICT", 409, {"version": "agent-child-stop-control-conflict/v1", "status": "running", "execution_revision": 7, "output": "private-sentinel"}),
])
async def test_stop_revision_conflict_rejects_malformed_or_extra_details(monkeypatch, code, status, control):
    monkeypatch.setenv("APP_ENV", "development")
    transport = httpx.MockTransport(lambda request: httpx.Response(status, json={
        "error_code": code, "message": "safe", "data": {"stop_control": control},
    }))
    client = CapabilityGatewayClient({}, "http://fixture", "fixture-test-token", transport)
    with pytest.raises(GatewayError) as caught:
        await client._post("/internal/agent/cancel", {}, 1)
    assert caught.value.details == {}
    assert "private-sentinel" not in str(caught.value)


@pytest.mark.asyncio
async def test_ordinary_error_does_not_expose_data_and_oversize_is_rejected(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    safe = {"version": "agent-child-stop-control-conflict/v1", "status": "running", "execution_revision": 7}
    responses = iter([
        httpx.Response(409, json={"error_code": "AGENT_ROUTE_CONFLICT", "data": {"stop_control": safe, "output": "private-sentinel"}}),
        httpx.Response(409, content=b"x" * (MAX_GATEWAY_RESPONSE_BYTES + 1)),
    ])
    transport = httpx.MockTransport(lambda request: next(responses))
    client = CapabilityGatewayClient({}, "http://fixture", "fixture-test-token", transport)
    with pytest.raises(GatewayError) as ordinary:
        await client._post("/internal/agent/cancel", {}, 1)
    assert ordinary.value.details == {}
    assert "private-sentinel" not in str(ordinary.value)
    with pytest.raises(GatewayError) as oversized:
        await client._post("/internal/agent/cancel", {}, 1)
    assert oversized.value.code == "GATEWAY_RESPONSE_TOO_LARGE"
    assert oversized.value.details == {}
