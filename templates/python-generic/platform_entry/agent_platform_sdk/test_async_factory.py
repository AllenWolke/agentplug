from __future__ import annotations

import pytest

from .async_factory import AsyncFactoryError, create_async_agent_app


async def _allow(_: dict[str, object]) -> dict[str, object]:
    return {}


async def _invoke(payload: dict[str, object]) -> dict[str, object]:
    return {"ok": payload.get("input")}


def _app():
    return create_async_agent_app(
        agent_id="demo-agent",
        version="1.0.0",
        capabilities=("invoke",),
        authorize=_allow,
        invoke=_invoke,
    )


async def _call(app, method: str, path: str, payload: bytes = b"{}"):
    sent = []
    messages = [{"type": "http.request", "body": payload, "more_body": False}]

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await app.asgi()({"method": method, "path": path, "headers": []}, receive, send)
    return sent


@pytest.mark.asyncio
async def test_async_factory_exposes_manifest_health_and_invoke() -> None:
    app = _app()
    health = await _call(app, "GET", "/health/ready")
    assert health[0]["status"] == 200
    manifest = await _call(app, "GET", "/.well-known/agent-manifest.json")
    assert manifest[0]["status"] == 200
    result = await _call(app, "POST", "/internal/agent-execution/v2/invoke", b'{"input":"ok"}')
    assert result[0]["status"] == 200


@pytest.mark.asyncio
async def test_async_factory_rejects_malformed_and_oversized_payload() -> None:
    app = create_async_agent_app(
        agent_id="demo-agent", version="1.0.0", capabilities=("invoke",), authorize=_allow, invoke=_invoke, max_body_bytes=4
    )
    malformed = await _call(app, "POST", "/internal/agent-execution/v2/invoke", b"not-json")
    assert malformed[0]["status"] == 400
    oversized = await _call(app, "POST", "/internal/agent-execution/v2/invoke", b'{"x":1}')
    assert oversized[0]["status"] == 400
    with pytest.raises(AsyncFactoryError):
        create_async_agent_app(agent_id="", version="1", capabilities=("invoke",), authorize=_allow, invoke=_invoke)


@pytest.mark.asyncio
async def test_async_factory_rejects_invalid_content_length() -> None:
    app = _app()
    sent = []
    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}
    async def send(message):
        sent.append(message)
    await app.asgi()({"method": "POST", "path": "/internal/agent-execution/v2/invoke", "headers": [(b"content-length", b"nope")]}, receive, send)
    assert sent[0]["status"] == 400
