from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_platform_sdk import ContextVerifier, ContextVerificationError, ExecuteRequest
from agent_platform_sdk.security import canonical_body_hash


def test_shared_resume_digest_matches_go_and_java() -> None:
    # Pin a cross-language digest, not the hash produced by the verifier itself.
    # 固定跨语言摘要，避免测试签名器与验签器共同漏掉恢复输入。
    fixture = (
        Path(__file__).resolve().parents[3]
        / "contracts/fixtures/execution-v2-request.json"
    )
    raw = json.loads(fixture.read_text(encoding="utf-8-sig"))
    raw["operation"] = "resume"
    raw["resume_input"] = {"decision": "approve", "reviewer_id": "reviewer-a"}
    assert (
        canonical_body_hash(ExecuteRequest.model_validate(raw))
        == "b3b300c491c0e717dd493556b96cef294c30fcc93cd3eea53fb5beb986a1530a"
    )


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def request() -> ExecuteRequest:
    return ExecuteRequest.model_validate(
        {
            "protocol_version": "agent-execution/v2",
            "context_token": "x" * 32,
            "scope": {
                "tenant_id": "t",
                "department_id": "d",
                "application_id": "a",
                "agent_instance_id": "i",
                "installation_id": "installation-i",
                "agent_id": "agent",
                "agent_version_id": "v1",
                "principal_type": "user",
                "principal_id": "u",
                "session_id": "s",
                "run_id": "r",
                "authorization_epoch": 2,
                "trace_id": "a" * 32,
            },
            "operation": "invoke",
            "idempotency_key": "idem-key",
            "input_schema": "schema://qa/v1",
            "input": {
                "question": "what",
                "policy_snapshot": {"content_hash": "snapshot-hash"},
            },
        }
    )


def sign(private: Ed25519PrivateKey, req: ExecuteRequest, **overrides: object) -> str:
    now = int(time.time())
    claims = {
        "iss": "platform",
        "aud": "agent-runtime",
        "subject_type": "user",
        "sub": "u",
        "tenant_id": "t",
        "application_id": "a",
        "agent_instance_id": "i",
        "installation_id": "installation-i",
        "authorization_epoch": 2,
        "actions": ["invoke"],
        "policy_snapshot_hash": "snapshot-hash",
        "body_hash": canonical_body_hash(req),
        "iat": now,
        "exp": now + 60,
        "jti": "one",
    }
    claims.update(overrides)
    h, p = b64(json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()), b64(
        json.dumps(claims).encode()
    )
    return f"{h}.{p}.{b64(private.sign(f'{h}.{p}'.encode()))}"


def test_verifies_signature_scope_action_and_body() -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    req = request()
    assert (
        ContextVerifier(public, "platform", "agent-runtime")
        .verify(sign(private, req), req)
        .claims["sub"]
        == "u"
    )


def test_environment_verifier_honors_deployment_audience_and_rejects_foreign(monkeypatch, tmp_path):
    private = Ed25519PrivateKey.generate()
    key_file = tmp_path / "verification-public.key"
    key_file.write_text(base64.b64encode(private.public_key().public_bytes_raw()).decode())
    monkeypatch.delenv("PLATFORM_CONTEXT_PUBLIC_KEY", raising=False)
    monkeypatch.setenv("PLATFORM_CONTEXT_PUBLIC_KEY_FILE", str(key_file))
    monkeypatch.setenv("PLATFORM_CONTEXT_ISSUER", "isolated-platform")
    monkeypatch.setenv("PLATFORM_CONTEXT_AUDIENCE", "isolated-agents")
    req = request()
    verifier = ContextVerifier.from_environment()
    verifier.verify(sign(private, req, iss="isolated-platform", aud="isolated-agents"), req)
    with pytest.raises(ContextVerificationError, match="aud"):
        verifier.verify(sign(private, req, iss="isolated-platform", aud="agent-runtime"), req)
    ContextVerifier.from_environment(audience="explicit-agent").verify(sign(private, req, iss="isolated-platform", aud="explicit-agent"), req)
    monkeypatch.setenv("PLATFORM_CONTEXT_AUDIENCE", " ")
    with pytest.raises(RuntimeError, match="nonblank"):
        ContextVerifier.from_environment()


def test_rejects_body_or_scope_drift() -> None:
    private = Ed25519PrivateKey.generate()
    verifier = ContextVerifier(
        private.public_key().public_bytes_raw(), "platform", "agent-runtime"
    )
    req = request()
    token = sign(private, req)
    changed = req.model_copy(update={"input": {"question": "changed"}})
    with pytest.raises(ContextVerificationError):
        verifier.verify(token, changed)


def test_resume_decision_is_signed_and_cannot_be_replaced() -> None:
    private = Ed25519PrivateKey.generate()
    verifier = ContextVerifier(
        private.public_key().public_bytes_raw(), "platform", "agent-runtime"
    )
    req = request().model_copy(
        update={"operation": "resume", "resume_input": {"decision": "reject"}}
    )
    token = sign(private, req, actions=["resume"])
    verifier.verify(token, req)
    for changes in (
        {"resume_input": {"decision": "approve"}},
        {"operation": "run"},
        {"resume_input": None},
        {"idempotency_key": "another-command-key"},
    ):
        with pytest.raises(ContextVerificationError):
            verifier.verify(token, req.model_copy(update=changes))
    # A valid token for one Run cannot authorize the same decision on another.
    # 一个 Run 的有效令牌不能授权另一个 Run 执行相同审核决定。
    other_scope = req.scope.model_copy(update={"run_id": "another-run"})
    with pytest.raises(ContextVerificationError):
        verifier.verify(token, req.model_copy(update={"scope": other_scope}))
    # An Ed25519-valid token carrying the wrong digest must also fail closed.
    # 即使 Ed25519 签名有效，只要正文摘要错误也必须拒绝。
    wrong_digest = sign(private, req, actions=["resume"], body_hash="0" * 64)
    with pytest.raises(ContextVerificationError):
        verifier.verify(wrong_digest, req)


def test_workload_headers_are_deployment_credentials(monkeypatch, tmp_path):
    from agent_platform_sdk.security import signed_internal_headers
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("INTERNAL_SIGNING_SECRET", "fixture-signing-secret-value-12345678")
    monkeypatch.setenv("AGENT_CLIENT_ID", "fixture-worker")
    monkeypatch.delenv("AGENT_CLIENT_SECRET", raising=False)
    secret_file = tmp_path / "workload-secret"
    secret_file.write_text("w" * 43, encoding="utf-8")
    monkeypatch.setenv("AGENT_CLIENT_SECRET_FILE", str(secret_file))
    headers = signed_internal_headers(b'{"input":{}}', "internal", method="POST", request_target="/internal/context/renew")
    assert headers["X-Agent-Client-ID"] == "fixture-worker"
    assert headers["X-Agent-Client-Secret"] == "w" * 43
    monkeypatch.delenv("AGENT_CLIENT_ID")
    with pytest.raises(RuntimeError, match="configured together"):
        signed_internal_headers(b"{}", "internal", method="POST", request_target="/internal/model/embed")
