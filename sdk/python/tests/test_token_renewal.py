"""Short capability renewal does not bypass current platform authorization."""

import asyncio
import base64
import json
import time

import httpx
import pytest
from pydantic import BaseModel

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError


class TestContext(BaseModel):
    __test__ = False
    platform_context_token: str


def token(claims):
    raw = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    # Transport fixture only; real signature and IAM rejection are Go server tests.
    return "fixture." + raw + ".fixture"


@pytest.mark.asyncio
async def test_concurrent_clients_renew_once_before_capability(monkeypatch):
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "test-secret")
    old = {
        "exp": int(time.time()) - 5,
        "execution_revision": 3,
        "lease_token_hash": "a" * 64,
        "run_id": "run-a",
    }
    renewed = token({**old, "exp": int(time.time()) + 120})
    context = TestContext(platform_context_token=token(old))
    renewal_calls = 0
    capability_calls = 0

    async def respond(request):
        nonlocal renewal_calls, capability_calls
        if request.url.path == "/internal/context/renew":
            renewal_calls += 1
            await asyncio.sleep(0.02)
            return httpx.Response(200, json={"data": {"context_token": renewed}})
        capability_calls += 1
        assert request.headers["X-Platform-Context"] == "Bearer " + renewed
        assert (
            json.loads(request.content)["context"]["platform_context_token"] == renewed
        )
        return httpx.Response(200, json={"data": {"ok": True}})

    clients = [
        CapabilityGatewayClient(
            context,
            base_url="http://platform.test",
            token="test-internal",
            transport=httpx.MockTransport(respond),
        )
        for _ in range(8)
    ]
    results = await asyncio.gather(
        *(
            client._post("/internal/model/embed", {"texts": ["test"]}, 2)
            for client in clients
        )
    )
    assert all(result == {"ok": True} for result in results)
    assert renewal_calls == 1 and capability_calls == 8


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["revoked", "changed_scope", "invalid_response"])
async def test_renewal_denial_has_zero_capability_calls(monkeypatch, failure):
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "test-secret")
    old = {
        "exp": int(time.time()) - 5,
        "execution_revision": 3,
        "lease_token_hash": "a" * 64,
        "run_id": "run-a",
    }
    original = token(old)
    context = TestContext(platform_context_token=original)

    def respond(request):
        assert request.url.path == "/internal/context/renew"
        if failure == "revoked":
            return httpx.Response(403, json={"code": "RENEWAL_DENIED"})
        if failure == "invalid_response":
            return httpx.Response(200, text="not json")
        return httpx.Response(
            200,
            json={
                "data": {
                    "context_token": token(
                        {**old, "exp": int(time.time()) + 120, "run_id": "foreign-run"}
                    )
                }
            },
        )

    client = CapabilityGatewayClient(
        context,
        base_url="http://platform.test",
        token="test-internal",
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(GatewayError) as error:
        await client._post("/internal/tool/invoke", {"name": "write"}, 2)
    assert error.value.code == (
        "CAPABILITY_RENEWAL_UNAVAILABLE"
        if failure == "invalid_response"
        else "CAPABILITY_RENEWAL_DENIED"
    )
    assert context.platform_context_token == original


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", [False, True])
async def test_live_validation_reauthorizes_unexpired_signed_execution(monkeypatch, denied):
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "test-secret")
    old = {"exp": int(time.time()) + 120, "execution_revision": 3, "run_id": "run-a"}
    original = token(old)
    renewed = token({**old, "exp": int(time.time()) + 180})
    context = TestContext(platform_context_token=original)
    calls = []

    def respond(request):
        calls.append(request.url.path)
        assert request.headers["X-Platform-Context"] == "Bearer " + original
        return httpx.Response(403, json={"code": "DENIED"}) if denied else httpx.Response(200, json={"data": {"context_token": renewed}})

    client = CapabilityGatewayClient(context, base_url="http://platform.test", token="test-internal", transport=httpx.MockTransport(respond))
    if denied:
        with pytest.raises(GatewayError) as error:
            await client.validate_current_execution()
        assert error.value.code == "CAPABILITY_RENEWAL_DENIED"
        assert context.platform_context_token == original
    else:
        await client.validate_current_execution()
        assert context.platform_context_token == renewed
    assert calls == ["/internal/context/renew"]


@pytest.mark.asyncio
async def test_live_validation_rejects_missing_execution_claims_before_transport():
    context = TestContext(platform_context_token="unsigned")
    client = CapabilityGatewayClient(context, base_url="http://platform.test", token="test-internal",
                                     transport=httpx.MockTransport(lambda _: pytest.fail("invalid context reached transport")))
    with pytest.raises(GatewayError) as error:
        await client.validate_current_execution()
    assert error.value.code == "CAPABILITY_RENEWAL_DENIED"
