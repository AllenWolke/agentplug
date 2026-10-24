import asyncio
from types import SimpleNamespace

import pytest

from agent_platform_sdk import call_observation as observation
from agent_platform_sdk.capability_client import CapabilityGatewayClient,GatewayError


@pytest.mark.asyncio
@pytest.mark.parametrize("mode",["ok","error","cancel"])
async def test_observation_never_retries_or_exposes_payload_credentials_or_exceptions(monkeypatch,mode):
    monkeypatch.setenv("AGENT_PLATFORM_CAPABILITY_TIMING","1")
    events=[];calls=[]
    monkeypatch.setattr(observation,"_emit",events.append)
    failure=GatewayError("STATE_RESULT_UNKNOWN","secret provider body")
    async def call():
        calls.append(1)
        if mode=="error":raise failure
        if mode=="cancel":raise asyncio.CancelledError()
        return {"secret_answer":"private"}
    args=(SimpleNamespace(task_id="private-task",platform_context_token="private-token"),
        "/internal/state/checkpoint",{"operation":"save","namespace":"checkpoint-cursor","key":"private-key","value":"private"},call)
    if mode=="ok":assert (await observation.observed_call(*args))["secret_answer"]=="private"
    else:
        with pytest.raises(GatewayError if mode=="error" else asyncio.CancelledError) as caught:
            await observation.observed_call(*args)
        if mode=="error":assert caught.value is failure
    assert calls==[1] and len(events)==1
    event=events[0]
    assert event["path"]=="/internal/state/checkpoint" and event["namespace"]=="checkpoint-cursor"
    assert event["operation"]=="save" and event["elapsed_ms"]>=0
    assert event["status"]=={"ok":"completed","error":"failed","cancel":"cancelled"}[mode]
    assert "private" not in str(event) and "secret" not in str(event)


@pytest.mark.asyncio
async def test_disabled_and_failed_sink_do_not_change_call_or_error(monkeypatch):
    monkeypatch.delenv("AGENT_PLATFORM_CAPABILITY_TIMING",raising=False)
    def forbidden(_):pytest.fail("disabled timing emitted")
    monkeypatch.setattr(observation,"_emit",forbidden)
    async def call():return "original"
    assert await observation.observed_call({},"private-path",{},call)=="original"
    monkeypatch.setenv("AGENT_PLATFORM_CAPABILITY_TIMING","1")
    def broken(_):raise OSError("private sink")
    monkeypatch.setattr(observation,"_emit",broken)
    assert await observation.observed_call({},"private-path",{},call)=="original"
    failure=GatewayError("UPSTREAM_TIMEOUT","private")
    async def fails():raise failure
    with pytest.raises(GatewayError) as caught:await observation.observed_call({},"private-path",{},fails)
    assert caught.value is failure


@pytest.mark.asyncio
async def test_client_and_renewal_are_observed_at_existing_boundaries(monkeypatch):
    from agent_platform_sdk import token_renewal
    monkeypatch.setenv("AGENT_PLATFORM_CAPABILITY_TIMING","1")
    events=[];calls=[]
    monkeypatch.setattr(observation,"_emit",events.append)
    # Invoke the production public wrapper; avoid constructing a transport or
    # weakening a signed request fixture for this timing-only boundary test.
    client=object.__new__(CapabilityGatewayClient);client._context=SimpleNamespace(task_id="fixture")
    async def request(path,payload,timeout):calls.append((path,timeout));return {"receipt":"original"}
    client._post_request=request
    assert await client._post("/internal/tool/invoke",{},2)=={"receipt":"original"}
    await token_renewal.renew_context_token(SimpleNamespace(task_id="fixture"),"unused","unused")
    assert calls==[("/internal/tool/invoke",2)]
    assert [row["path"] for row in events]==["/internal/tool/invoke","/internal/context/renew"]
