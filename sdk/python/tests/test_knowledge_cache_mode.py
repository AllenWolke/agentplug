import json

import httpx
import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient


@pytest.mark.asyncio
async def test_knowledge_cache_modes_keep_legacy_input_and_distinct_idempotency(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    requests = []

    def handle(request):
        requests.append(json.loads(request.content)["input"])
        return httpx.Response(200, json={"data": {"references": []}})

    client = CapabilityGatewayClient({}, "http://fixture", "fixture-token", httpx.MockTransport(handle))
    for mode in ("", "use", "cold", "bypass"):
        await client.search_knowledge("question", "docs", cache_mode=mode)
    assert "cache_mode" not in requests[0]
    assert [item["cache_mode"] for item in requests[1:]] == ["use", "cold", "bypass"]
    assert len({item["idempotency_key"] for item in requests}) == 4
    with pytest.raises(ValueError, match="cache_mode"):
        await client.search_knowledge("question", "docs", cache_mode="unknown")
    assert len(requests) == 4


@pytest.mark.asyncio
async def test_answer_knowledge_uses_common_signed_client_and_mode_bound_keys(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    requests = []

    def handle(request):
        requests.append((request.url.path, json.loads(request.content)["input"]))
        return httpx.Response(200, json={"data": {"text": "answer", "answer_cache_hit": True, "usage": {"input_tokens": 0, "output_tokens": 0}}})

    client = CapabilityGatewayClient({}, "http://fixture", "fixture-token", httpx.MockTransport(handle))
    for mode in ("use", "cold", "bypass"):
        result = await client.answer_knowledge("question", "docs", cache_mode=mode)
        assert result["answer_cache_hit"] and result["usage"]["input_tokens"] == 0
    assert all(path == "/internal/knowledge/answer" for path, _ in requests)
    assert len({payload["idempotency_key"] for _, payload in requests}) == 3
    with pytest.raises(ValueError, match="cache_mode"):
        await client.answer_knowledge("question", "docs", cache_mode="unknown")
    assert len(requests) == 3
