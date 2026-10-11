"""Capability PEP tests for the python-generic template.

python-generic 模板的能力 PEP 测试：用 Go SDK 一次性签名的共享夹具，证明本模板
vendored SDK 的规范化正文哈希与平台/其他语言模板逐字节一致，并证明被篡改的能力
一律被拒绝。
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Callable

import pytest

import server
from agent_platform_sdk import ContextVerifier, ContextVerificationError, ExecuteRequest
from agent_platform_sdk.security import canonical_body_hash

FIXTURE = next((parent / "contracts" / "fixtures" / "execution-v2-capability.json"
                for parent in Path(__file__).resolve().parents
                if (parent / "contracts" / "fixtures" / "execution-v2-capability.json").is_file()),
               Path(__file__).resolve().parent / "missing-shared-capability-fixture.json")


def load_fixture() -> dict[str, Any]:
    if not FIXTURE.exists():
        pytest.skip("shared capability fixture not present (standalone generated project)")
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def build_verifier(fixture: dict[str, Any]) -> ContextVerifier:
    return ContextVerifier(
        base64.b64decode(fixture["public_key_b64"]), fixture["issuer"], fixture["audience"],
        now=lambda: fixture["now"],
    )


def test_canonical_body_hash_matches_the_sdk_fixture() -> None:
    fixture = load_fixture()
    request = ExecuteRequest.model_validate(fixture["request"])
    assert canonical_body_hash(request) == fixture["body_hash"]


def test_gateway_signed_capability_is_accepted() -> None:
    fixture = load_fixture()
    request = ExecuteRequest.model_validate(fixture["request"])
    trusted = build_verifier(fixture).verify(fixture["token"], request)
    assert trusted.claims["sub"] == "user-a"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: request.__setitem__("context_token", "0123456789abcdef0123456789abcdef"),
        lambda request: request["input"].__setitem__("injected", "value"),
        lambda request: request.__setitem__("idempotency_key", "other-key"),
        lambda request: request["input"].pop("policy_snapshot", None),
        lambda request: request.__setitem__("operation", "run"),
    ],
    ids=["length-only-token", "tampered-body", "tampered-idempotency", "missing-snapshot", "undelegated-action"],
)
def test_tampered_capabilities_are_rejected(mutate: Callable[[dict[str, Any]], None]) -> None:
    fixture = load_fixture()
    verifier = build_verifier(fixture)
    payload = json.loads(json.dumps(fixture["request"]))
    mutate(payload)
    request = ExecuteRequest.model_validate(payload)
    # The server always verifies the token carried by the envelope itself
    # (after the bearer binding), so a swapped token must fail here.
    # 服务器校验的永远是信封自身携带的令牌（先过 bearer 绑定），
    # 因此被替换的令牌必须在此失败。
    with pytest.raises(ContextVerificationError):
        verifier.verify(request.context_token, request)


def test_wrong_audience_and_expired_lifetime_are_rejected() -> None:
    fixture = load_fixture()
    request = ExecuteRequest.model_validate(fixture["request"])
    key = base64.b64decode(fixture["public_key_b64"])
    other = ContextVerifier(key, fixture["issuer"], "another-agent", now=lambda: fixture["now"])
    with pytest.raises(ContextVerificationError):
        other.verify(fixture["token"], request)
    expired = ContextVerifier(key, fixture["issuer"], fixture["audience"], now=lambda: fixture["now"] + 3600)
    with pytest.raises(ContextVerificationError):
        expired.verify(fixture["token"], request)


def test_public_key_refuses_to_start_without_platform_material(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "AGENT_PLATFORM_PUBLIC_KEY_BASE64",
        "PLATFORM_CONTEXT_PUBLIC_KEY",
        "AGENT_PLATFORM_PUBLIC_KEY_FILE",
        "PLATFORM_CONTEXT_PUBLIC_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError):
        server.public_key_from_env()


def test_public_key_accepts_the_platform_env_and_file_forms(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fixture = load_fixture()
    monkeypatch.delenv("AGENT_PLATFORM_PUBLIC_KEY_BASE64", raising=False)
    monkeypatch.setenv("PLATFORM_CONTEXT_PUBLIC_KEY", fixture["public_key_b64"])
    assert server.public_key_from_env() is not None
    monkeypatch.delenv("PLATFORM_CONTEXT_PUBLIC_KEY", raising=False)
    key_file = tmp_path / "platform.pub"
    key_file.write_text(fixture["public_key_b64"], encoding="utf-8")
    monkeypatch.setenv("AGENT_PLATFORM_PUBLIC_KEY_FILE", str(key_file))
    assert server.public_key_from_env() is not None
