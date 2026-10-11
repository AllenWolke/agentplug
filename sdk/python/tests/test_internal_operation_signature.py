"""Cross-language operation binding and replay negatives / 跨语言操作签名回归。"""

import pytest
import httpx

from agent_platform_sdk.capability_client import CapabilityGatewayClient

from agent_platform_sdk.security import (
    internal_signature_payload,
    signed_internal_headers,
    verify_internal_signature,
)


def test_canonical_operation_vector():
    assert internal_signature_payload(b"abc", "POST", "/internal/model/embed") == (
        b'["platform-capability/v2","POST","/internal/model/embed",'
        b'"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"]'
    )


@pytest.mark.parametrize(
    "body,method,target",
    [
        (b"abc", "POST", "/internal/knowledge/search"),
        (b"abc", "GET", "/internal/model/embed"),
        (b"changed", "POST", "/internal/model/embed"),
        (b"abc", "POST", "/internal/model/embed?operation=other"),
    ],
)
def test_signature_rejects_changed_operation(monkeypatch, body, method, target):
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "test-only-secret")
    signature = signed_internal_headers(
        b"abc", "test-token", method="POST", request_target="/internal/model/embed"
    )["X-Context-Signature"]
    assert verify_internal_signature(
        b"abc", signature, method="POST", request_target="/internal/model/embed"
    )
    assert not verify_internal_signature(
        body, signature, method=method, request_target=target
    )


@pytest.mark.asyncio
async def test_real_client_signs_transmitted_target_and_body(monkeypatch):
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "test-only-secret")
    seen = []

    def respond(request):
        target = request.url.raw_path.decode("ascii")
        seen.append(target)
        assert verify_internal_signature(
            request.content,
            request.headers["X-Context-Signature"],
            method=request.method,
            request_target=target,
        )
        assert not verify_internal_signature(
            request.content,
            request.headers["X-Context-Signature"],
            method=request.method,
            request_target="/internal/tool/invoke",
        )
        return httpx.Response(200, json={"data": {"ok": True}})

    client = CapabilityGatewayClient(
        {},
        base_url="http://platform.test",
        token="test-token",
        transport=httpx.MockTransport(respond),
    )
    for target in ("/internal/model/embed", "/internal/knowledge/search"):
        assert await client._post(target, {"question": "文档检索"}, 2) == {"ok": True}
    assert seen == ["/internal/model/embed", "/internal/knowledge/search"]
