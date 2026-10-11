import socket

import pytest

from agent_platform_sdk.grpc_bridge import start_grpc_bridge


@pytest.mark.asyncio
async def test_explicit_loopback_grpc_bridge_listens_and_stops(monkeypatch):
    monkeypatch.setenv("AGENT_GRPC_BIND_HOST", "127.0.0.1")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = await start_grpc_bridge(port, "http://127.0.0.1:1")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    finally:
        await server.stop(0)


@pytest.mark.asyncio
async def test_invalid_grpc_bind_address_is_rejected(monkeypatch):
    monkeypatch.setenv("AGENT_GRPC_BIND_HOST", "invalid-host")
    with pytest.raises(ValueError):
        await start_grpc_bridge(9001, "http://127.0.0.1:1")
