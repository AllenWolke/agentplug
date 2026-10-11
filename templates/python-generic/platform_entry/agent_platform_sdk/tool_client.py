"""Shared Tool capability transport for generated Agents.

All authorization, confirmation, idempotency, and auditing are owned by the
platform. Agents call only this transport and never call Backend/Harness APIs.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from typing import Any

import httpx
from .capability_client import GatewayError, MAX_GATEWAY_RESPONSE_BYTES
from .token_renewal import TokenRenewalError, renew_context_token

from .security import (
    encode_internal_envelope,
    internal_token,
    signed_internal_headers,
)
from .agent_group_resume import current_agent_group_resume
from .graph_context import resolve_graph_context

logger = logging.getLogger(__name__)


class ToolGatewayError(GatewayError):
    def __init__(self, code: str, message: str):
        super().__init__(code, message)
        self.code = code


def _platform_base_url() -> str:
    value = os.getenv("PLATFORM_CAPABILITY_URL", "").strip().rstrip("/")
    if not value:
        raise ToolGatewayError(
            "PLATFORM_CAPABILITY_URL_REQUIRED",
            "configure the modular platform capability endpoint",
        )
    return value


def _trace_id(context: Any) -> str:
    return str(getattr(context, "trace_id", ""))


async def invoke_tool(
    name: str,
    payload: dict,
    context: Any,
    token: str,
    confirmed: bool = False,
) -> dict:
    context = resolve_graph_context(context)
    _enforce_agent_group_resume_boundary(context)
    # Only an explicit in-progress receipt permits polling with the same key.
    # Each attempt renews the context and passes through current platform ACLs.
    for attempt in range(5):
        try:
            return await _invoke_tool_once(name, payload, context, token, confirmed)
        except ToolGatewayError as exc:
            if exc.code != "TOOL_INVOCATION_IN_PROGRESS" or attempt == 4:
                raise
            await asyncio.sleep(0.05 * 2**attempt)
    raise AssertionError("tool receipt polling exhausted")


async def _invoke_tool_once(
    name: str,
    payload: dict,
    context: Any,
    token: str,
    confirmed: bool,
) -> dict:
    _enforce_agent_group_resume_boundary(context)
    try:
        await renew_context_token(context, _platform_base_url(), token)
    except TokenRenewalError as exc:
        raise ToolGatewayError(exc.code, "current execution renewal denied") from exc
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    binding = (
        getattr(context, "task_id", "")
        or getattr(context, "session_id", "")
        or getattr(context, "request_id", "")
    )
    call_id = (
        "py-" + hashlib.sha256(f"{binding}:{name}:{canonical}".encode()).hexdigest()
    )
    body = encode_internal_envelope(
        context,
        {"name": name, "call_id": call_id, "payload": payload, "confirmed": confirmed},
    )
    async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
        response = await client.post(
            _platform_base_url() + "/internal/tool/invoke",
            content=body,
            headers=signed_internal_headers(
                body,
                token,
                _trace_id(context),
                getattr(context, "platform_context_token", ""),
                method="POST",
                request_target=httpx.URL(
                    _platform_base_url() + "/internal/tool/invoke"
                ).raw_path.decode("ascii"),
            ),
        )
    if len(response.content) > MAX_GATEWAY_RESPONSE_BYTES:
        raise ToolGatewayError(
            "GATEWAY_RESPONSE_TOO_LARGE", "response exceeded the limit"
        )
    if response.status_code >= 400:
        # Preserve the bounded platform error code/message for operators and
        # retry classification; never include the request body or credentials.
        # 保留有界的平台错误码/消息，便于定位 4xx/5xx；绝不回显请求正文或凭证。
        try:
            error_payload = response.json()
        except (json.JSONDecodeError, ValueError):
            error_payload = {}
        if not isinstance(error_payload, dict):
            raise ToolGatewayError(
                "INVALID_TOOL_RESPONSE", "error response must be an object"
            )
        code = str(
            error_payload.get("error_code")
            or error_payload.get("code")
            or "TOOL_INVOKE_FAILED"
        )[:64]
        message = str(error_payload.get("message") or f"HTTP {response.status_code}")[
            :256
        ]
        safe_code = code if re.fullmatch(r"[A-Z0-9_]{1,64}", code) else "TOOL_INVOKE_FAILED"
        logger.warning(
            "capability_call_failed path=/internal/tool/invoke status=%s code=%s",
            response.status_code,
            safe_code,
        )
        raise ToolGatewayError(code, message)
    try:
        data = response.json()
        return data["data"]["data"]
    except (KeyError, TypeError, json.JSONDecodeError, ValueError) as exc:
        raise ToolGatewayError(
            "INVALID_TOOL_RESPONSE", "tool response is malformed"
        ) from exc


def _enforce_agent_group_resume_boundary(context: Any) -> None:
    binding = current_agent_group_resume.get()
    if binding is None:
        return
    if (getattr(context, "task_id", "") != binding.run_id
            or getattr(context, "input_fingerprint", "") != binding.input_fingerprint
            or getattr(context, "execution_revision", 0) != binding.execution_revision
            or getattr(context, "execution_operation", "") != "resume"):
        raise ToolGatewayError("RUN_RESUME_UNCONFIRMED", "resume context does not match the signed group")
    raise ToolGatewayError("AGENT_GROUP_RESUME_BOUNDARY", "tool invocation is outside the original gather")
