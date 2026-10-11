"""Renew short capabilities against live platform facts / 按平台实时事实续签短令牌。"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import weakref
from typing import Any

import httpx

from .security import encode_internal_envelope, signed_internal_headers

_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()


class TokenRenewalError(RuntimeError):
    def __init__(self, message: str, code: str = "CAPABILITY_RENEWAL_DENIED") -> None:
        super().__init__(message)
        self.code = code


def _token(context: Any) -> str:
    return str(
        context.get("platform_context_token", "")
        if isinstance(context, dict)
        else getattr(context, "platform_context_token", "")
    )


def _claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        result = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        return result if isinstance(result, dict) else {}
    except (IndexError, ValueError, UnicodeError):
        return {}


async def renew_context_token(
    context: Any,
    base_url: str,
    internal_token: str,
    transport: httpx.AsyncBaseTransport | None = None,
    *,
    force: bool = False,
) -> None:
    token = _token(context)
    claims = _claims(token)
    if force and (not claims.get("execution_revision") or not isinstance(claims.get("exp"), int)):
        raise TokenRenewalError("live execution context required")
    # Parsing only decides when to ask; the server authenticates and reauthorizes.
    # 本地解析仅决定续签时机，不充当认证；服务端核对签名、IAM、Run 与租约。
    if (
        not claims.get("execution_revision")
        or not isinstance(claims.get("exp"), int)
        or (not force and claims["exp"] > time.time() + 15)
    ):
        return
    key = hashlib.sha256(token.encode()).hexdigest()
    lock = _locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _locks[key] = lock
    async with lock:
        if _token(context) != token:
            return
        target = base_url.rstrip("/") + "/internal/context/renew"
        body = encode_internal_envelope(context, {})
        headers = signed_internal_headers(
            body,
            internal_token,
            getattr(context, "trace_id", ""),
            token,
            method="POST",
            request_target=httpx.URL(target).raw_path.decode("ascii"),
        )
        try:
            async with httpx.AsyncClient(
                timeout=10, transport=transport, trust_env=False, follow_redirects=False
            ) as client:
                response = await client.post(target, content=body, headers=headers)
            if response.status_code in {401, 403}:
                raise TokenRenewalError("current execution renewal denied")
            if response.status_code != 200 or len(response.content) > 32768:
                raise TokenRenewalError(
                    "execution renewal unavailable", "CAPABILITY_RENEWAL_UNAVAILABLE"
                )
            refreshed = response.json().get("data", {}).get("context_token", "")
            next_claims = _claims(refreshed)
            binding = (
                "iss",
                "aud",
                "subject_type",
                "sub",
                "tenant_id",
                "department_id",
                "application_id",
                "installation_id",
                "agent_instance_id",
                "agent_id",
                "agent_version_id",
                "run_id",
                "session_id",
                "trace_id",
                "authorization_epoch",
                "actions",
                "body_hash",
                "policy_snapshot_hash",
                "execution_revision",
                "lease_token_hash",
            )
            if (
                not refreshed
                or any(next_claims.get(field) != claims.get(field) for field in binding)
                or not isinstance(next_claims.get("exp"), int)
                or next_claims["exp"] <= time.time() + 15
            ):
                raise TokenRenewalError("renewed execution binding invalid")
        except (httpx.HTTPError, ValueError, TypeError, AttributeError) as exc:
            raise TokenRenewalError(
                "execution renewal unavailable", "CAPABILITY_RENEWAL_UNAVAILABLE"
            ) from exc
        if isinstance(context, dict):
            context["platform_context_token"] = refreshed
        else:
            context.platform_context_token = refreshed
