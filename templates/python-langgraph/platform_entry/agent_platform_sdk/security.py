"""Ed25519 capability verification for Agent Execution services.

Agent 执行服务使用的 Ed25519 能力令牌校验。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import EventRequest, ExecuteRequest, validate_event_cursor


class ContextVerificationError(ValueError):
    """Raised when a platform capability cannot be trusted. / 平台能力令牌不可信。"""


@dataclass(frozen=True, slots=True)
class TrustedContext:
    claims: dict[str, Any]
    request: ExecuteRequest


# Internal service authentication is shared by every generated Agent.
# 内部服务认证由 SDK 统一提供，避免每个 Agent 复制一份安全实现。
DEVELOPMENT_ENVS = {"development", "dev", "local", "test"}
PLACEHOLDER_TOKENS = {"dev-internal-token", "change-me", "replace-me"}


def validate_deployed_model_mode() -> None:
    """Reject evaluation bypasses outside explicit development environments.

    显式开发环境之外拒绝评测直连和 Mock，防止绕过平台治理。
    """
    if os.getenv("APP_ENV", "").strip().lower() in DEVELOPMENT_ENVS:
        return
    if (
        os.getenv("EVAL_DIRECT_PROVIDER", "").strip()
        or os.getenv("EVAL_EXECUTION_MODE", "").strip()
    ):
        raise RuntimeError(
            "evaluation model overrides are forbidden in deployed Agents"
        )


def internal_token(explicit: str | None = None) -> str:
    """Resolve an internal credential without an implicit production secret.

    解析内部调用凭证，支持只读Secret挂载；生产环境禁止隐式开发令牌。
    """

    environment = os.getenv("APP_ENV", "").strip().lower()
    value = (
        explicit if explicit is not None else os.getenv("INTERNAL_TOKEN", "")
    ).strip()
    if explicit is None and not value:
        path = os.getenv("INTERNAL_TOKEN_FILE", "").strip()
        if path:
            try:
                value = Path(path).read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                # 不把底层解码错误中的密钥字节带入异常或启动日志。
                raise RuntimeError("unable to read INTERNAL_TOKEN_FILE") from None
            if not value:
                raise RuntimeError("INTERNAL_TOKEN_FILE must contain a non-empty secret")
    if environment in DEVELOPMENT_ENVS:
        return value or "dev-internal-token"
    if not value or value.lower() in PLACEHOLDER_TOKENS:
        raise RuntimeError(
            "INTERNAL_TOKEN must be an explicit non-placeholder secret outside development"
        )
    if environment in {"production", "prod"}:
        _validate_production_secret(value, "INTERNAL_TOKEN")
    return value


def internal_signing_secret(explicit: str | None = None) -> str:
    """Resolve the body-signing secret used for service-to-service calls.

    支持 Kubernetes Secret 文件挂载，生产环境缺少密钥时失败关闭。
    """

    value = (
        explicit if explicit is not None else os.getenv("INTERNAL_SIGNING_SECRET", "")
    ).strip()
    if not value:
        path = os.getenv("INTERNAL_SIGNING_SECRET_FILE", "").strip()
        if path:
            try:
                value = Path(path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise RuntimeError(
                    "unable to read INTERNAL_SIGNING_SECRET_FILE"
                ) from exc
    environment = os.getenv("APP_ENV", "").strip().lower()
    if environment in {"production", "prod"} and not value:
        raise RuntimeError("INTERNAL_SIGNING_SECRET must be configured in production")
    if environment in {"production", "prod"}:
        _validate_production_secret(value, "INTERNAL_SIGNING_SECRET")
    return value


def _validate_production_secret(value: str, name: str) -> None:
    if (
        len(value.encode("utf-8")) < 32
        or len(set(value)) < 2
        or any(
            marker in value.lower()
            for marker in (
                "replace-",
                "change-me",
                "changeme",
                "placeholder",
                "dev-internal",
                "dev-signing",
            )
        )
    ):
        raise RuntimeError(
            f"{name} must be a non-placeholder secret with at least 32 bytes in production"
        )


def signed_internal_headers(
    body: bytes,
    token: str,
    trace_id: str = "",
    platform_context_token: str = "",
    *,
    method: str,
    request_target: str,
) -> dict[str, str]:
    """Bind method, request target and exact body digest by HMAC.

    生成内部调用请求头，并用 HMAC 绑定精确请求正文。
    """

    client_id = os.getenv("AGENT_CLIENT_ID", "").strip()
    client_secret = os.getenv("AGENT_CLIENT_SECRET", "").strip()
    secret_file = os.getenv("AGENT_CLIENT_SECRET_FILE", "").strip()
    if not client_secret and secret_file:
        try:
            client_secret = Path(secret_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Agent credential file unavailable") from exc
    if bool(client_id) != bool(client_secret) or (client_secret and not 32 <= len(client_secret) <= 512):
        raise RuntimeError("Agent workload credentials must be configured together")
    headers = {"X-Internal-Token": token}
    if client_id:
        headers.update({"X-Agent-Client-ID": client_id, "X-Agent-Client-Secret": client_secret})
    if trace_id:
        headers["X-Trace-ID"] = trace_id
    if platform_context_token:
        headers["X-Platform-Context"] = "Bearer " + platform_context_token
    secret = internal_signing_secret()
    if secret:
        digest = hmac.new(
            secret.encode("utf-8"),
            internal_signature_payload(body, method, request_target),
            hashlib.sha256,
        ).hexdigest()
        headers["X-Context-Signature"] = "sha256=" + digest
    return headers


def internal_signature_payload(body: bytes, method: str, request_target: str) -> bytes:
    """Versioned unambiguous operation binding / 版本化、无歧义的操作绑定。"""
    if not request_target.startswith("/") or any(c in request_target for c in "\r\n"):
        raise ValueError("invalid internal request target")
    return json.dumps(
        [
            "platform-capability/v2",
            method.upper(),
            request_target,
            hashlib.sha256(body).hexdigest(),
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def verify_internal_signature(
    body: bytes, provided: str, *, method: str, request_target: str
) -> bool:
    """Verify a service-to-service body signature.

    校验服务间正文签名；开发环境无签名密钥时保持兼容，生产启动会拒绝。
    """

    secret = internal_signing_secret()
    if not secret:
        return True
    supplied = provided.strip()
    if supplied.startswith("sha256="):
        supplied = supplied[len("sha256=") :]
    expected = hmac.new(
        secret.encode("utf-8"),
        internal_signature_payload(body, method, request_target),
        hashlib.sha256,
    ).hexdigest()
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def encode_internal_envelope(context: Any, payload: Any) -> bytes:
    """Encode one canonical envelope so transmitted bytes and HMAC match.

    统一编码请求信封，确保传输正文与 HMAC 计算字节完全一致。
    """

    context_data = context.model_dump() if hasattr(context, "model_dump") else context
    raw = {"context": context_data, "input": payload}
    return json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_body_hash(request: ExecuteRequest) -> str:
    """Hash the immutable request envelope, excluding its bearer token.

    对不含 Bearer Token 的不可变请求信封求哈希，避免签名循环依赖。
    """

    # Go's generated contract omits optional zero-value scope fields
    # (`parent_run_id` and `delegation_depth`) via `omitempty`.  Excluding
    # Pydantic defaults keeps the canonical bytes identical across SDKs.
    # Go 生成的契约对可选零值作用域字段使用 `omitempty`；排除 Pydantic
    # 默认值，确保不同语言 SDK 的规范化字节完全一致。
    envelope = request.model_dump(
        exclude={"context_token"}, exclude_defaults=True, mode="json"
    )
    raw = json.dumps(
        envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def canonical_event_hash(request: EventRequest) -> str:
    validate_event_cursor(request.after_seq)
    envelope = request.model_dump(
        exclude={"context_token"}, exclude_defaults=True, mode="json"
    )
    raw = json.dumps(
        envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ContextVerifier:
    @classmethod
    def from_environment(cls, *, audience: str | None = None) -> ContextVerifier:
        """Load the operator's key/issuer/audience without accepting a request override."""
        raw = os.getenv("PLATFORM_CONTEXT_PUBLIC_KEY", "").strip()
        if not raw:
            path = os.getenv("PLATFORM_CONTEXT_PUBLIC_KEY_FILE", "").strip()
            if path:
                try:
                    raw = Path(path).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise RuntimeError("unable to read platform context public key") from exc
        if not raw:
            raise RuntimeError("PLATFORM_CONTEXT_PUBLIC_KEY is required")
        try:
            key = base64.b64decode(raw, validate=True)
            if len(key) != 32:
                raise ValueError("invalid Ed25519 public key length")
        except ValueError as exc:
            raise RuntimeError("PLATFORM_CONTEXT_PUBLIC_KEY must be a base64 Ed25519 key") from exc
        issuer = os.getenv("PLATFORM_CONTEXT_ISSUER", "platform")
        selected = audience if audience is not None else os.getenv("PLATFORM_CONTEXT_AUDIENCE", "agent-runtime")
        if any(not value or len(value) > 256 or value.strip() != value or any(ord(char) < 33 for char in value) for value in (issuer, selected)):
            raise RuntimeError("platform context issuer and audience must be explicit nonblank identifiers")
        return cls(key, issuer, selected)

    def __init__(
        self,
        public_key: bytes,
        issuer: str,
        audience: str,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._key = Ed25519PublicKey.from_public_bytes(public_key)
        self._issuer = issuer
        self._audience = audience
        # Injectable clock so shared fixtures with pinned timestamps verify
        # deterministically. / 可注入时钟，让钉死时间戳的共享夹具可确定性校验。
        self._now = now or (lambda: int(time.time()))

    def verify(self, token: str, request: ExecuteRequest) -> TrustedContext:
        try:
            header_part, payload_part, signature_part = token.split(".")
            header = json.loads(_decode(header_part))
            claims = json.loads(_decode(payload_part))
            self._key.verify(
                _decode(signature_part), f"{header_part}.{payload_part}".encode()
            )
        except Exception as exc:
            raise ContextVerificationError("invalid capability signature") from exc
        if header.get("alg") != "EdDSA":
            raise ContextVerificationError("invalid capability algorithm")
        now = self._now()
        scope = request.scope
        # The hash is both inside the body binding and an explicit capability
        # claim so downstream PEPs can authorize resources without trusting IDs.
        # 快照哈希既受正文签名保护，也作为显式声明供下游 PEP 使用。
        policy = request.input.get("policy_snapshot")
        if not isinstance(policy, dict) or not isinstance(
            policy.get("content_hash"), str
        ):
            raise ContextVerificationError("immutable policy snapshot is missing")
        expected = {
            "iss": self._issuer,
            "aud": self._audience,
            "subject_type": scope.principal_type,
            "sub": scope.principal_id,
            "tenant_id": scope.tenant_id,
            "application_id": scope.application_id,
            "agent_instance_id": scope.agent_instance_id,
            "installation_id": scope.installation_id,
            "authorization_epoch": scope.authorization_epoch,
            "policy_snapshot_hash": policy["content_hash"],
            "body_hash": canonical_body_hash(request),
        }
        mismatched = [
            key for key, value in expected.items() if claims.get(key) != value
        ]
        if mismatched:
            # Report field names only; values may contain tenant/user data and
            # must never be emitted to logs. / 只报告字段名，绝不记录租户或用户值。
            raise ContextVerificationError(
                "capability scope mismatch: " + ",".join(mismatched)
            )
        if request.operation not in claims.get("actions", []):
            raise ContextVerificationError("operation is not delegated")
        if not isinstance(claims.get("iat"), int) or not isinstance(
            claims.get("exp"), int
        ):
            raise ContextVerificationError("capability time claims missing")
        if (
            claims["iat"] > now + 30
            or claims["exp"] <= now
            or claims["exp"] - claims["iat"] > 300
        ):
            raise ContextVerificationError(
                "capability expired or outside lifetime policy"
            )
        return TrustedContext(claims=claims, request=request)

    def verify_event(self, token: str, request: EventRequest) -> dict[str, Any]:
        """Verify an events-only capability. / 校验仅允许订阅事件的能力令牌。"""
        try:
            validate_event_cursor(request.after_seq)
            event_body_hash = canonical_event_hash(request)
        except (TypeError, ValueError) as exc:
            raise ContextVerificationError("invalid event cursor") from exc
        try:
            header_part, payload_part, signature_part = token.split(".")
            header = json.loads(_decode(header_part))
            claims = json.loads(_decode(payload_part))
            self._key.verify(
                _decode(signature_part), f"{header_part}.{payload_part}".encode()
            )
        except Exception as exc:
            raise ContextVerificationError("invalid capability signature") from exc
        if header.get("alg") != "EdDSA":
            raise ContextVerificationError("invalid capability algorithm")
        scope = request.scope
        expected = {
            "iss": self._issuer,
            "aud": self._audience,
            "subject_type": scope.principal_type,
            "sub": scope.principal_id,
            "tenant_id": scope.tenant_id,
            "application_id": scope.application_id,
            "agent_instance_id": scope.agent_instance_id,
            "installation_id": scope.installation_id,
            "authorization_epoch": scope.authorization_epoch,
            "policy_snapshot_hash": request.policy_snapshot_hash,
            "body_hash": event_body_hash,
        }
        if any(claims.get(key) != value for key, value in expected.items()):
            raise ContextVerificationError("capability scope mismatch")
        if "events" not in claims.get("actions", []):
            raise ContextVerificationError("events operation is not delegated")
        now = self._now()
        if not isinstance(claims.get("iat"), int) or not isinstance(
            claims.get("exp"), int
        ):
            raise ContextVerificationError("capability time claims missing")
        if (
            claims["iat"] > now + 30
            or claims["exp"] <= now
            or claims["exp"] - claims["iat"] > 300
        ):
            raise ContextVerificationError(
                "capability expired or outside lifetime policy"
            )
        return claims
