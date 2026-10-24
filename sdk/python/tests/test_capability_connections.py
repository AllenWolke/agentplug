"""Real loopback HTTP/1.1, with no vendor, IAM fixture changes or business Run."""
import asyncio
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import httpx
import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.capability_connections import capability_connection_lifespan, connection_transport, _pools


@asynccontextmanager
async def echo_server():
    state = {"connections":0, "requests":[], "tasks":set(), "release":asyncio.Event()}
    async def serve(reader, writer):
        state["connections"] += 1
        task = asyncio.current_task()
        state["tasks"].add(task)
        try:
            while True:
                try:
                    raw = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                lines = raw.decode("ascii").split("\r\n")
                headers = {key.lower():value for key,value in
                           (line.split(": ",1) for line in lines[1:] if ": " in line)}
                body = await reader.readexactly(int(headers.get("content-length","0")))
                state["requests"].append({"headers":headers, "body":json.loads(body or b"{}")})
                if "/slow " in lines[0]:
                    await state["release"].wait()
                result = json.dumps({"data":{"confirmed":True}}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: fixture=one-user-only\r\nContent-Length: "+str(len(result)).encode()+b"\r\n\r\n"+result)
                await writer.drain()
        finally:
            state["tasks"].discard(task)
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(serve,"127.0.0.1",0)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}", state
    finally:
        state["release"].set()
        server.close()
        await server.wait_closed()
        for task in list(state["tasks"]):
            task.cancel()
        await asyncio.gather(*list(state["tasks"]), return_exceptions=True)


class Context(SimpleNamespace):
    def model_dump(self):
        return vars(self)


@pytest.mark.asyncio
async def test_real_connection_reuse_keeps_per_request_authority_and_cookie_isolation(monkeypatch):
    monkeypatch.setenv("APP_ENV","test")
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET","synthetic-local-signing-fixture")
    async with echo_server() as (origin,state):
        async with capability_connection_lifespan():
            for index in range(20):
                client=CapabilityGatewayClient(Context(task_id=str(index),actor_id=f"user-{index}",
                    platform_context_token=f"synthetic-Token-{index}",trace_id="fixture-trace"),base_url=origin,token="synthetic-internal-fixture")
                assert await client._post("/internal/prompt/resolve",{"ordinal":index},5)=={"confirmed":True}
            assert state["connections"] == 1
            assert len(state["requests"]) == 20
            for index, request in enumerate(state["requests"]):
                assert "cookie" not in request["headers"]
                assert request["body"]["context"]["actor_id"] == f"user-{index}"
                assert request["body"]["input"]["ordinal"] == index
                assert request["headers"]["x-platform-context"] == f"Bearer synthetic-Token-{index}"
                assert request["headers"]["x-context-signature"].startswith("sha256=")
            assert len({r["headers"]["x-context-signature"] for r in state["requests"]}) == 20
        assert asyncio.get_running_loop() not in _pools


@pytest.mark.asyncio
async def test_timeout_is_not_retried_and_independent_request_can_continue(monkeypatch):
    monkeypatch.setenv("APP_ENV","test")
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET","synthetic-local-signing-fixture")
    async with echo_server() as (origin,state):
        async with capability_connection_lifespan():
            client=CapabilityGatewayClient(Context(platform_context_token="fixture"),base_url=origin,token="synthetic-internal-fixture")
            with pytest.raises(GatewayError) as failed:
                await client._post("/slow",{},.02)
            assert failed.value.code == "UPSTREAM_TIMEOUT"
            assert len(state["requests"]) == 1
            assert await client._post("/independent",{},5) == {"confirmed":True}
            assert len(state["requests"]) == 2


@pytest.mark.asyncio
async def test_pool_is_bounded_nested_lifespans_and_explicit_transport_stay_owned():
    explicit=httpx.MockTransport(lambda request:httpx.Response(200))
    assert connection_transport("http://127.0.0.1") is None
    async with capability_connection_lifespan():
        owner=_pools[asyncio.get_running_loop()]
        first=connection_transport("http://127.0.0.1:1")
        async with capability_connection_lifespan():
            assert connection_transport("http://127.0.0.1:1").transport is first.transport
            await first.aclose()  # borrowing client cannot close shared sockets
            assert owner.active
        assert owner.active and owner.owners == 1
        for index in range(2,9):
            assert connection_transport(f"http://127.0.0.1:{index}") is not None
        assert connection_transport("http://127.0.0.1:9") is None
        assert len(owner.transports) == 8
        assert connection_transport("http://127.0.0.1",explicit) is explicit
        assert connection_transport("http://user:pass@127.0.0.1") is None
    assert not owner.active and not owner.transports
    with pytest.raises(RuntimeError,match="lifespan closed"):
        await first.handle_async_request(httpx.Request("GET","http://127.0.0.1"))
