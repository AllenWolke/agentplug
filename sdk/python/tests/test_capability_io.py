import asyncio
import pytest
from agent_platform_sdk.capability_io import LimitedCapabilityClient
from agent_platform_sdk.capability_client import GatewayError
from test_public_harness import Fixture, input


@pytest.mark.asyncio
async def test_model_send_capacity_does_not_hold_tools_and_completed_harness_replay_is_free():
    capacity=asyncio.Semaphore(2)
    active={"model":0,"tool":0}; peaks=dict(active)
    class Client(Fixture):
        async def _post(self,path,payload,timeout):
            kind="model" if path.endswith("model/generate") else "tool" if path.endswith("tool/invoke") else None
            if kind:
                active[kind]+=1; peaks[kind]=max(peaks[kind],active[kind])
                try:
                    await asyncio.sleep(.01 if kind=="model" else .03)
                    return await super()._post(path,payload,timeout)
                finally:active[kind]-=1
            return await super()._post(path,payload,timeout)
    originals=[Client() for _ in range(12)]
    wrapped=[LimitedCapabilityClient(client,{"/internal/model/generate":capacity}) for client in originals]
    async def run(client):return await client.run_harness(input(),key="capacity",confirmation_token="opaque")
    first=await asyncio.gather(*(run(client) for client in wrapped))
    assert all(row["status"]=="completed" for row in first)
    assert peaks["model"]==2 and peaks["tool"]>2
    assert await asyncio.gather(*(run(client) for client in wrapped))==first
    assert all(client.models==2 and client.effects==1 for client in originals)


@pytest.mark.asyncio
async def test_limited_client_preserves_unknown_receipt_without_a_duplicate_write():
    original=Fixture(unknown=True)
    client=LimitedCapabilityClient(original,{"/internal/model/generate":asyncio.Semaphore(1)})
    for code in ("TOOL_RESULT_UNKNOWN", "HARNESS_RECONCILIATION_REQUIRED"):
        with pytest.raises(GatewayError,match=code):
            await client.run_harness(input(),key="unknown",confirmation_token="opaque")
    assert original.models==original.effects==original.queries==1
