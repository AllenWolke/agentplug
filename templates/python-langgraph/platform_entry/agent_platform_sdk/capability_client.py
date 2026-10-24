"""Shared HTTP capability client for generated Agents.

所有生成 Agent 共用同一套平台能力 HTTP 客户端；业务 Agent 只负责把领域
输入转换成 capability payload，不再复制鉴权、签名、大小限制和错误归一化。
"""

from __future__ import annotations

import hashlib
import asyncio
import json
import logging
import math
import os
import re
import time
from typing import Any

import httpx

from .security import encode_internal_envelope, internal_token, signed_internal_headers
from .agent_group_resume import current_agent_group_resume
from .token_renewal import TokenRenewalError, renew_context_token
from .graph_context import resolve_graph_context
from .capability_connections import connection_transport


class GatewayError(RuntimeError):
    """Stable error exposed by the platform capability boundary."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None, *, status_code: int | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.details = dict(details or {})
        self.status_code=status_code


MAX_GATEWAY_RESPONSE_BYTES = 1 << 20
_STOP_CONTROL_CONFLICT_VERSION = "agent-child-stop-control-conflict/v1"
DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS = float(
    os.environ.get("LLM_GATEWAY_REQUEST_TIMEOUT_SECONDS", "310")
)
_logger = logging.getLogger(__name__)
_AGENT_EDGE_WHITESPACE = " \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def _child_stop_control_error_details(code: str, status_code: int, response_data: Any) -> dict[str, Any]:
    """Retain only the exact bounded stop-CAS hint; discard all other error data."""
    if code != "AGENT_STOP_REVISION_CONFLICT" or status_code != 409 or not isinstance(response_data, dict):
        return {}
    if set(response_data) != {"stop_control"}:
        return {}
    control = response_data.get("stop_control")
    if not isinstance(control, dict) or set(control) != {"version", "status", "execution_revision"}:
        return {}
    revision = control.get("execution_revision")
    if (control.get("version") != _STOP_CONTROL_CONFLICT_VERSION
            or control.get("status") not in {"accepted", "running", "waiting"}
            or type(revision) is not int or not 1 <= revision <= 9223372036854775807):
        return {}
    return {"stop_control": {
        "version": _STOP_CONTROL_CONFLICT_VERSION,
        "status": control["status"],
        "execution_revision": revision,
    }}


def _agent_operation_key(value: Any) -> bool:
    """Match the bounded router/admission operation-key contract."""
    if (not isinstance(value, str) or not value or value.strip(_AGENT_EDGE_WHITESPACE) != value
            or any(character in value for character in "*\x00\r\n")):
        return False
    try:
        return len(value.encode("utf-8")) <= 128
    except UnicodeEncodeError:
        return False


class CapabilityGatewayClient:
    """Call Model/Knowledge/Memory/Prompt capabilities through the platform.

    The context object is intentionally structural: Python, Go and Java Agent
    adapters can provide their own typed context without coupling the SDK to a
    domain package. / 上下文采用结构化协议，避免 SDK 依赖具体业务包。
    """

    def __init__(
        self,
        context: Any,
        base_url: str | None = None,
        token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._context = resolve_graph_context(context)
        configured_base = base_url or os.environ.get("PLATFORM_CAPABILITY_URL") or ""
        self._base = configured_base.strip().rstrip("/")
        if not self._base:
            raise GatewayError(
                "PLATFORM_CAPABILITY_URL_REQUIRED",
                "configure the modular platform capability endpoint",
            )
        self._token = internal_token(token)
        self._transport = transport

    def _current_group_resume_binding(self):
        binding = current_agent_group_resume.get()
        if binding is not None and (
                getattr(self._context, "task_id", "") != binding.run_id
                or getattr(self._context, "input_fingerprint", "") != binding.input_fingerprint
                or getattr(self._context, "execution_revision", 0) != binding.execution_revision
                or getattr(self._context, "execution_operation", "") != "resume"):
            raise GatewayError("RUN_RESUME_UNCONFIRMED", "resume context does not match the signed group")
        return binding

    def _enforce_group_resume_gather_only(self, *, gather: bool = False) -> None:
        binding = self._current_group_resume_binding()
        if binding is None:
            return
        if not gather or not binding.consume_gather_permission():
            raise GatewayError("AGENT_GROUP_RESUME_BOUNDARY", "only the bound original gather is allowed")

    def _enforce_group_resume_request(self, path: str, payload: dict, binding) -> None:
        """Keep a resumed handler inside the original gather's read-only boundary."""
        if binding is None:
            return
        if binding.gathered and not binding.pause_required:
            # Lifecycle permits ordinary, freshly authorized business reads
            # only after this exact bound gather returned terminal success.
            return
        if (path == "/internal/state/checkpoint"
                and payload == {
                    "operation": "load",
                    "namespace": "coordination",
                    "key": binding.group_key,
                    "schema_id": "schema://agentplug/agent-group/v1",
                    "revision": 0,
                }):
            return
        if path == "/internal/runtime/harness-policy" and payload in ({}, {"include_batch": True}):
            # Read-only policy discovery is allowed during the bound gather.
            return
        if (path == "/internal/agent/gather" and payload == {
                "operation_key": binding.operation_key,
        } and binding.consume_gather_request(binding.operation_key)):
            return
        raise GatewayError("AGENT_GROUP_RESUME_BOUNDARY", "only the original gather read is allowed")

    async def _post(self, path: str, payload: dict, timeout: float) -> dict:
        from .call_observation import observed_call
        return await observed_call(self._context,path,payload,
            lambda:self._post_with_tool_receipt(path,payload,timeout))

    async def _post_with_tool_receipt(self, path: str, payload: dict, timeout: float) -> dict:
        deadline = (time.monotonic() + timeout if path == "/internal/tool/invoke"
                    and isinstance(timeout, (int, float)) and math.isfinite(timeout) and timeout > 0 else None)
        try:
            return await self._post_request(path, payload, timeout)
        except (httpx.TransportError, GatewayError) as error:
            if isinstance(error, GatewayError) and error.code != "UPSTREAM_TIMEOUT":
                raise
            # Read the original receipt; this is never a second tool/model
            # invocation. The ordinary request still owns its original budget.
            if (path != "/internal/tool/invoke" or not isinstance(payload, dict)
                    or not isinstance(payload.get("name"), str) or not payload["name"]
                    or not isinstance(payload.get("call_id"), str) or not payload["call_id"]
                    or not isinstance(payload.get("payload"), dict)):
                raise
            remaining = min(5.0, deadline - time.monotonic()) if deadline is not None else 0
            if remaining <= 0:
                raise GatewayError("TOOL_RESULT_UNKNOWN", "original tool dispatch requires reconciliation") from error
            command = {key: payload[key] for key in ("name", "call_id", "payload")}
            if payload.get("confirmation_token"):
                command["confirmation_token"] = payload["confirmation_token"]
            cause = type(error).__name__ if isinstance(error, httpx.TransportError) else "UPSTREAM_TIMEOUT"
            _logger.warning("tool_response_observation_lost cause=%s recovery=original_receipt", cause)
            try:
                async with asyncio.timeout(remaining):
                    receipt = await self._post("/internal/tool/receipt", command, remaining)
            except GatewayError as lookup_error:
                # A receipt error must never enter the caller's invoke retry,
                # approval retry or budget-completion branch. Keep dispatch
                # unknown; current authority loss still stops the execution.
                if lookup_error.code in {"TOOL_CONFIRMATION_REQUIRED", "MODEL_BUDGET_EXCEEDED"}:
                    raise GatewayError("CAPABILITY_DENIED", "original tool receipt is not authorized") from lookup_error
                from .optimization import authority_failure
                if authority_failure(lookup_error):
                    raise
                raise GatewayError("TOOL_RESULT_UNKNOWN", "original tool receipt is unavailable") from lookup_error
            except (httpx.TransportError, TimeoutError) as lookup_error:
                raise GatewayError("TOOL_RESULT_UNKNOWN", "original tool receipt is unavailable") from lookup_error
            if (not isinstance(receipt, dict) or receipt.get("version") != "tool-receipt/v1"
                    or receipt.get("tool_name") != payload["name"]
                    or receipt.get("call_id") != payload["call_id"]):
                raise GatewayError("TOOL_RECEIPT_REJECTED", "original tool receipt binding is invalid")
            if receipt.get("status") != "completed":
                raise GatewayError("TOOL_RESULT_UNKNOWN", "original tool dispatch requires reconciliation")
            result = receipt.get("receipt")
            observation = result.get("observation") if isinstance(result, dict) else None
            if (not isinstance(result, dict) or "data" not in result
                    or not isinstance(observation, dict) or observation.get("version") != "runtime-observation/v1"
                    or observation.get("tool_name") != payload["name"]
                    or observation.get("call_id") != payload["call_id"]
                    or observation.get("status") != "succeeded" or observation.get("effect") != "completed"
                    or observation.get("instruction_trust") != "untrusted_data"):
                raise GatewayError("TOOL_RECEIPT_REJECTED", "original tool observation is invalid")
            _logger.info("tool_response_observation_recovered source=original_receipt")
            return result

    async def _post_request(self, path: str, payload: dict, timeout: float) -> dict:
        resume_binding = self._current_group_resume_binding()
        self._enforce_group_resume_request(path, payload, resume_binding)
        post_gather = (resume_binding is not None and resume_binding.gathered
                       and not resume_binding.pause_required)
        if resume_binding is None or post_gather:
            try:
                await renew_context_token(
                    self._context, self._base, self._token, self._transport
                )
            except TokenRenewalError as exc:
                raise GatewayError(exc.code, "current execution renewal denied") from exc
        body = encode_internal_envelope(self._context, payload)
        async with httpx.AsyncClient(
            timeout=timeout,
            transport=connection_transport(self._base, self._transport),
            trust_env=False,
        ) as client:
            try:
                response = await client.post(
                    self._base + path,
                    content=body,
                    headers=signed_internal_headers(
                        body,
                        self._token,
                        getattr(self._context, "trace_id", ""),
                        getattr(self._context, "platform_context_token", ""),
                        method="POST",
                        request_target=httpx.URL(self._base + path).raw_path.decode(
                            "ascii"
                        ),
                    ),
                )
            except httpx.TimeoutException as error:
                # This is an observation failure, not proof that the operation
                # was unsent. Leave durable intent/receipts to their workflow;
                # never retry, release a reservation or select another model.
                raise GatewayError("UPSTREAM_TIMEOUT", "capability observation timed out") from error
        if len(response.content) > MAX_GATEWAY_RESPONSE_BYTES:
            raise GatewayError(
                "GATEWAY_RESPONSE_TOO_LARGE", "response exceeded the limit"
            )
        if response.status_code >= 400:
            try:
                response_data = response.json()
            except (json.JSONDecodeError, ValueError):
                raise GatewayError(
                    "UPSTREAM_HTTP_ERROR",
                    f"upstream returned HTTP {response.status_code}",
                ) from None
            if not isinstance(response_data, dict):
                raise GatewayError(
                    "INVALID_GATEWAY_RESPONSE", "error response must be an object"
                )
            error_code = str(
                    response_data.get("error_code")
                    or response_data.get("code", "50003")
                )
            observation = response_data.get("data", {}).get("observation") if isinstance(response_data.get("data"), dict) else None
            if isinstance(observation, dict) and observation.get("version") == "runtime-observation/v1" and observation.get("effect") == "unknown":
                error_code = "TOOL_RESULT_UNKNOWN"
            details = _child_stop_control_error_details(error_code, response.status_code, response_data.get("data"))
            # 只记录固定路径、状态及受限错误码，不记录正文、消息或认证凭据。
            diagnostic_code = error_code if re.fullmatch(r"[A-Z0-9_]{1,64}", error_code) else "INVALID_UPSTREAM_CODE"
            _logger.warning("capability_call_failed path=%s status=%d code=%s", path, response.status_code, diagnostic_code)
            raise GatewayError(
                diagnostic_code,
                "platform capability rejected",
                details=details, status_code=response.status_code,
            )
        try:
            response_data = response.json()
        except (json.JSONDecodeError, ValueError):
            raise GatewayError(
                "INVALID_GATEWAY_RESPONSE", "success response is not JSON"
            ) from None
        if not isinstance(response_data, dict) or not isinstance(
            response_data.get("data"), dict
        ):
            raise GatewayError("INVALID_GATEWAY_RESPONSE", "response data is missing")
        return response_data["data"]

    async def validate_current_execution(self) -> None:
        """Reauthorize the signed run, lease, caller and workload at the platform.

        Uses the shared renewal capability even for an unexpired token; a local
        signature check or an old shared-credential public query is insufficient.
        """
        binding = self._current_group_resume_binding()
        if binding is not None and not (binding.gathered and not binding.pause_required):
            raise GatewayError("AGENT_GROUP_RESUME_BOUNDARY", "execution renewal is outside the original gather")
        try:
            await renew_context_token(self._context, self._base, self._token, self._transport, force=True)
        except TokenRenewalError as exc:
            raise GatewayError(exc.code, "current execution validation denied") from exc

    def _idempotency_key(self, prefix: str, identity: dict[str, Any]) -> str:
        canonical = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        binding = (
            getattr(self._context, "task_id", "")
            or getattr(self._context, "session_id", "")
            or getattr(self._context, "request_id", "")
        )
        return prefix + hashlib.sha256(f"{binding}:{canonical}".encode()).hexdigest()

    async def chat(
        self,
        messages: list[dict],
        temperature: float = 0.3,
        max_tokens: int = 2048,
        timeout: float = DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS,
        step_name: str = "model.generate",
        *, require_json: bool = False, response_schema: dict | None = None, response_schema_mode: str = "",
    ) -> dict[str, Any]:
        identity = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "usage_step": step_name,
            "prompt_template_hash": getattr(self._context, "prompt_template_hash", ""),
        }
        if type(require_json) is not bool:
            raise ValueError("require_json must be a boolean")
        if require_json:
            identity["require_json"] = True
        from .response_schema import schema_request
        schema, mode = schema_request(response_schema, response_schema_mode, require_json)
        if schema is not None:
            identity.update(response_schema=schema, response_schema_mode=mode)
        identity["idempotency_key"] = self._idempotency_key("model-", identity)
        data = await self._post("/internal/model/generate", identity, timeout)
        from .model_usage import chat_usage
        usage = data.get("usage", {})
        result = {
            "text": data["text"],
            "model": data.get("model", ""),
            "usage": chat_usage(usage),
        }
        # Retain actual platform references. Selection remains a Run preference;
        # this API grants no Agent override or provider-specific routing client.
        for field in ("routing", "route_execution", "billing", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"):
            if field in data:
                result[field] = data[field]
        return result

    async def embed(
        self,
        texts: list[str],
        timeout: float = DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS,
        step_name: str = "knowledge.embedding",
    ) -> list[list[float]]:
        if not texts:
            raise ValueError("texts is required")
        data = await self._post(
            "/internal/model/embed", {"texts": texts, "usage_step": step_name}, timeout
        )
        return data["vectors"]

    async def generate_with_functions(
        self, input: dict, max_rounds: int = 4,
        timeout: float = DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS,
    ) -> dict:
        """Bounded native tool loop; all tool execution remains in the platform.

        Sensitive-tool confirmation is never inferred from a model suggestion.
        A stable operation key reproduces the same model/tool ledger identities.
        """
        if type(max_rounds) is not int or not 1 <= max_rounds <= 8:
            raise ValueError("max_rounds must be between 1 and 8")
        current = json.loads(json.dumps(input, ensure_ascii=False))
        messages = current.get("messages")
        key = current.get("idempotency_key")
        if not isinstance(messages, list) or not messages or not isinstance(key, str) or not key:
            raise ValueError("messages and stable idempotency_key required")
        def step_key(round: int, phase: str) -> str:
            serialized = json.dumps([key, round, phase], ensure_ascii=False, separators=(",", ":"))
            return "function-" + hashlib.sha256(serialized.encode()).hexdigest()
        for round in range(max_rounds):
            current["messages"] = messages
            current["idempotency_key"] = step_key(round, "model")
            result = await self._post("/internal/model/generate", current, timeout)
            if result.get("completion_status") == "incomplete":
                return result
            calls = result.get("tool_calls")
            if not calls and result.get("completion_status") != "tool_calls":
                return result
            if not isinstance(calls, list) or not calls or len(calls) > 32:
                raise GatewayError("FUNCTION_RESPONSE_INVALID", "invalid tool calls")
            if round == max_rounds - 1:
                raise GatewayError("FUNCTION_ROUND_LIMIT", "tool round limit reached")
            bindings = result.get("function_bindings")
            if not isinstance(bindings, dict):
                raise GatewayError("FUNCTION_RESPONSE_INVALID", "published function bindings missing")
            messages.append({"role": "assistant", "content": result.get("text", ""), "tool_calls": calls})
            for call in calls:
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict):
                    raise GatewayError("FUNCTION_RESPONSE_INVALID", "invalid function call")
                tool = bindings.get(function.get("name"))
                call_id = call.get("id")
                try:
                    arguments = json.loads(function.get("arguments", ""))
                except (ValueError, TypeError):
                    raise GatewayError("FUNCTION_RESPONSE_INVALID", "invalid function arguments") from None
                if not isinstance(tool, str) or not tool or not isinstance(call_id, str) or not call_id or not isinstance(arguments, dict):
                    raise GatewayError("FUNCTION_RESPONSE_INVALID", "invalid function arguments")
                receipt = await self._post("/internal/tool/invoke", {
                    "name": tool, "call_id": step_key(round, call_id),
                    "payload": arguments, "confirmed": False,
                }, timeout)
                context_receipt = receipt
                if "observation" in receipt:
                    observation = receipt["observation"]
                    expected_call_id = step_key(round, call_id)
                    if not isinstance(observation, dict) or observation.get("version") != "runtime-observation/v1" or observation.get("tool_name") != tool or observation.get("call_id") != expected_call_id or observation.get("status") not in ("succeeded", "failed", "timeout", "cancelled") or observation.get("effect") != "completed" or observation.get("instruction_trust") != "untrusted_data" or "context_output" not in observation:
                        raise GatewayError("TOOL_OBSERVATION_REJECTED", "tool observation is invalid or incomplete")
                    encoded_context = json.dumps(observation["context_output"], ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
                    if len(encoded_context) > 2048:
                        raise GatewayError("TOOL_OBSERVATION_REJECTED", "tool context exceeds its public limit")
                    context_receipt = {"version": observation["version"], "tool_name": tool, "status": observation["status"], "error_type": observation.get("error_type", ""), "effect": observation["effect"], "instruction_trust": "untrusted_data", "context_truncated": observation.get("context_truncated", False), "output_truncated": observation.get("truncated", False), "context_output": observation["context_output"]}
                messages.append({"role": "tool", "tool_call_id": call_id, "content": json.dumps(context_receipt, ensure_ascii=False, separators=(",", ":"))})
        raise GatewayError("FUNCTION_ROUND_LIMIT", "tool round limit reached")

    async def read_agent_admission_state(self, operation_key: str, ordinal: int, child_key: str, input_fingerprint: str, output_schema: str, timeout: float = 30) -> dict:
        """Metadata-only proof of the original prepared/admitted slot; no dispatch."""
        self._enforce_group_resume_gather_only()
        valid_hash = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        if (not _agent_operation_key(operation_key) or type(ordinal) is not int or not 0 <= ordinal <= 15
                or not valid_hash(child_key) or not valid_hash(input_fingerprint)
                or not isinstance(output_schema, str) or not output_schema.startswith("schema://")
                or len(output_schema.encode("utf-8")) > 256 or any(c in output_schema for c in "*\x00\r\n\t ")):
            raise GatewayError("REQUEST_INVALID", "fixed admission binding required")
        result = await self._post("/internal/agent/admission-state", {"operation_key": operation_key, "ordinal": ordinal}, timeout)
        state = result.get("admission_state")
        if (not isinstance(state, dict) or state.get("version") != "agent-child-admission-state/v1"
                or not self._context.task_id or state.get("parent_run_id") != self._context.task_id
                or state.get("operation_key") != operation_key or type(state.get("ordinal")) is not int or state["ordinal"] != ordinal
                or state.get("child_key") != child_key or state.get("input_fingerprint") != input_fingerprint
                or state.get("output_schema") != output_schema or type(state.get("revision")) is not int or not 2 <= state["revision"] <= (1 << 63) - 1):
            raise GatewayError("AGENT_ADMISSION_STATE_REJECTED", "admission snapshot does not match the saved binding")
        if state.get("status") == "preparing":
            valid = state["revision"] == 2 and state.get("child_run_id") == ""
        else:
            valid = (state.get("status") in ("accepted", "running", "completed", "failed", "cancelled", "uncertain")
                     and state["revision"] >= 3 and state.get("child_run_id") == "child-" + child_key[:48])
        if not valid:
            raise GatewayError("AGENT_ADMISSION_STATE_REJECTED", "invalid admission lifecycle snapshot")
        return result

    async def run_agent_group(self, inputs: list[dict], *, key: str, operation_key: str, task_type: str, timeout: float = 30) -> dict:
        """Durable fixed-plan delegation; does not poll or resend uncertain admission."""
        from .coordination import run_agent_group
        return await run_agent_group(self, inputs, key=key, operation_key=operation_key,
                                     task_type=task_type, timeout=timeout)

    async def route_agents(self, operation_key: str, task_type: str, count: int = 1, timeout: float = 30) -> dict:
        """Plan/reserve authorized targets; does not dispatch or grant authority."""
        self._enforce_group_resume_gather_only()
        if not _agent_operation_key(operation_key) or not _agent_operation_key(task_type) or type(count) is not int or not 1 <= count <= 16:
            raise GatewayError("REQUEST_INVALID", "bounded routing command required")
        result = await self._post("/internal/agent/route", {"operation_key": operation_key, "task_type": task_type, "count": count}, timeout)
        route = result.get("route")
        if (not isinstance(route, dict) or route.get("version") != "agent-route/v1" or route.get("operation_key") != operation_key
                or route.get("task_type") != task_type or not getattr(self._context, "task_id", "")
                or route.get("parent_run_id") != self._context.task_id or type(route.get("child_depth")) is not int
                or not 1 <= route["child_depth"] <= 4 or not isinstance(route.get("targets"), list) or len(route["targets"]) != count):
            raise GatewayError("AGENT_ROUTE_REJECTED", "route does not match the current execution")
        seen = set()
        for target in route["targets"]:
            if (not isinstance(target, dict) or any(not _agent_operation_key(target.get(key)) for key in ("installation_id", "agent_id", "version_id"))
                    or target["installation_id"] in seen):
                raise GatewayError("AGENT_ROUTE_REJECTED", "invalid or duplicate route target")
            seen.add(target["installation_id"])
            for key in ("input_schema", "output_schema"):
                schema = target.get(key)
                if (not isinstance(schema, str) or not schema.startswith("schema://")
                        or len(schema.encode("utf-8")) > 256 or any(c in schema for c in "*\x00\r\n\t ")):
                    raise GatewayError("AGENT_ROUTE_REJECTED", "invalid route schema")
        return result

    async def prepare_agent_child(self, operation_key: str, ordinal: int, input_schema: str, input: dict, timeout: float = 30) -> dict:
        """Freeze a saved route target's input; does not admit or dispatch a Run."""
        self._enforce_group_resume_gather_only()
        if (not _agent_operation_key(operation_key) or type(ordinal) is not int or not 0 <= ordinal <= 15
                or not isinstance(input_schema, str) or not input_schema.startswith("schema://")
                or len(input_schema.encode("utf-8")) > 256 or any(c in input_schema for c in "*\x00\r\n\t ")
                or not isinstance(input, dict) or "policy_snapshot" in input):
            raise GatewayError("REQUEST_INVALID", "fixed route ordinal and bounded input required")
        try:
            encoded = json.dumps(input, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(encoded) > 65536:
                raise ValueError("input too large")
            frozen = json.loads(encoded)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise GatewayError("REQUEST_INVALID", "input must be bounded JSON") from exc
        result = await self._post("/internal/agent/prepare", {"operation_key": operation_key, "ordinal": ordinal,
                                  "expected_revision": 1, "input_schema": input_schema, "input": frozen}, timeout)
        prepared = result.get("preparation")
        if (not isinstance(prepared, dict) or prepared.get("version") != "agent-child-preparation/v1"
                or not getattr(self._context, "task_id", "") or prepared.get("parent_run_id") != self._context.task_id
                or prepared.get("operation_key") != operation_key or type(prepared.get("ordinal")) is not int
                or prepared["ordinal"] != ordinal or prepared.get("status") != "preparing"
                or type(prepared.get("revision")) is not int or prepared["revision"] != 2
                or prepared.get("input_schema") != input_schema
                or any(not isinstance(prepared.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", prepared[key]) is None
                       for key in ("child_key", "input_fingerprint"))):
            raise GatewayError("AGENT_PREPARATION_REJECTED", "preparation does not match the current execution")
        return result

    async def cancel_agent_child(self, operation_key: str, ordinal: int, child_key: str, expected_execution_revision: int, timeout: float = 30) -> dict:
        """Persist stop intent; pending states do not acknowledge remote termination."""
        self._enforce_group_resume_gather_only()
        if (not _agent_operation_key(operation_key) or type(ordinal) is not int or not 0 <= ordinal <= 15
                or not isinstance(child_key, str) or re.fullmatch(r"[0-9a-f]{64}", child_key) is None
                or type(expected_execution_revision) is not int or not 1 <= expected_execution_revision <= 9223372036854775807):
            raise GatewayError("REQUEST_INVALID", "fixed child and execution revision required")
        result = await self._post("/internal/agent/cancel", {"operation_key": operation_key, "ordinal": ordinal,
                                  "expected_execution_revision": expected_execution_revision}, timeout)
        cancelled = result.get("cancellation")
        if (not isinstance(cancelled, dict) or cancelled.get("version") != "agent-child-cancellation/v1"
                or not getattr(self._context, "task_id", "") or cancelled.get("parent_run_id") != self._context.task_id
                or cancelled.get("operation_key") != operation_key or type(cancelled.get("ordinal")) is not int or cancelled["ordinal"] != ordinal
                or cancelled.get("child_key") != child_key or cancelled.get("child_run_id") != "child-" + child_key[:48]
                or type(cancelled.get("execution_revision")) is not int or not 1 <= cancelled["execution_revision"] <= 9223372036854775807
                or cancelled.get("status") not in ("cancelling", "recovering", "cancelled", "completed", "failed")):
            raise GatewayError("AGENT_CANCELLATION_REJECTED", "cancellation does not match current child")
        return result

    async def admit_agent_child(self, operation_key: str, ordinal: int, child_key: str, input_fingerprint: str, timeout: float = 30) -> dict:
        """Admit frozen input once. Reconcile unknown outcomes through read_agent_child."""
        self._enforce_group_resume_gather_only()
        if (not _agent_operation_key(operation_key) or type(ordinal) is not int or not 0 <= ordinal <= 15
                or any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                       for value in (child_key, input_fingerprint))):
            raise GatewayError("REQUEST_INVALID", "fixed preparation binding required")
        result = await self._post("/internal/agent/admit", {"operation_key": operation_key, "ordinal": ordinal, "expected_revision": 2}, timeout)
        admitted = result.get("admission")
        if (not isinstance(admitted, dict) or admitted.get("version") != "agent-child-admission/v1"
                or not getattr(self._context, "task_id", "") or admitted.get("parent_run_id") != self._context.task_id
                or admitted.get("operation_key") != operation_key or type(admitted.get("ordinal")) is not int or admitted["ordinal"] != ordinal
                or admitted.get("child_key") != child_key or admitted.get("child_run_id") != "child-" + child_key[:48]
                or admitted.get("input_fingerprint") != input_fingerprint or type(admitted.get("revision")) is not int or admitted["revision"] < 3
                or admitted.get("status") not in ("accepted", "running", "completed", "failed", "cancelled", "uncertain")):
            raise GatewayError("AGENT_ADMISSION_REJECTED", "admission does not match frozen preparation")
        return result

    async def read_agent_child(self, operation_key: str, ordinal: int, child_key: str, output_schema: str, timeout: float = 30) -> dict:
        """Read an immediate child's untrusted output without dispatch or side effects."""
        self._enforce_group_resume_gather_only()
        if (not _agent_operation_key(operation_key) or type(ordinal) is not int or not 0 <= ordinal <= 15
                or not isinstance(child_key, str) or re.fullmatch(r"[0-9a-f]{64}", child_key) is None
                or not isinstance(output_schema, str) or not output_schema.startswith("schema://")
                or len(output_schema.encode("utf-8")) > 256 or any(c in output_schema for c in "*\x00\r\n\t ")):
            raise GatewayError("REQUEST_INVALID", "fixed child and output schema required")
        result = await self._post("/internal/agent/child", {"operation_key": operation_key, "ordinal": ordinal}, timeout)
        return self._validate_agent_child_result(result, getattr(self._context, "task_id", ""), operation_key, ordinal, child_key, output_schema)

    @staticmethod
    def _validate_agent_child_result(result: dict, run_id: str, operation_key: str, ordinal: int, child_key: str, output_schema: str) -> dict:
        child = result.get("child")
        if (not isinstance(child, dict) or child.get("version") != "agent-child-result/v1"
                or not run_id or child.get("parent_run_id") != run_id
                or child.get("operation_key") != operation_key or type(child.get("ordinal")) is not int or child["ordinal"] != ordinal
                or child.get("child_key") != child_key or child.get("child_run_id") != "child-" + child_key[:48]
                or type(child.get("execution_revision")) is not int or child["execution_revision"] < 1
                or child.get("status") not in ("accepted", "running", "waiting", "completed", "failed", "cancelled", "cancelling", "recovering", "uncertain")
                or child.get("output_schema") != output_schema or child.get("instruction_trust") != "untrusted_data"
                or type(child.get("output_bytes")) is not int or child["output_bytes"] < 0
                or type(child.get("output_omitted")) is not bool or "output" not in child):
            raise GatewayError("AGENT_CHILD_REJECTED", "child result does not match current execution")
        output, size, omitted = child["output"], child["output_bytes"], child["output_omitted"]
        if output is not None:
            if (not isinstance(output, dict) or child["status"] != "completed" or omitted or not 0 < size <= 16384
                    or not isinstance(child.get("output_digest"), str) or re.fullmatch(r"[0-9a-f]{64}", child["output_digest"]) is None):
                raise GatewayError("AGENT_CHILD_REJECTED", "invalid child output envelope")
            try:
                if len(json.dumps(output, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 98304:
                    raise ValueError("oversized output")
            except (ValueError, TypeError, UnicodeError) as exc:
                raise GatewayError("AGENT_CHILD_REJECTED", "child output must be bounded JSON") from exc
        elif (child.get("output_digest", "") != "" or (omitted and (child["status"] != "completed" or size <= 16384))
              or (not omitted and (child["status"] == "completed" or size != 0))):
            raise GatewayError("AGENT_CHILD_REJECTED", "invalid omitted child output envelope")
        return result

    async def gather_agent_children(self, operation_key: str, bindings: list[dict], timeout: float = 30) -> dict:
        """Read one admitted plan; ordinal-ordered saved bindings are mandatory."""
        self._enforce_group_resume_gather_only(gather=True)
        if not _agent_operation_key(operation_key) or not isinstance(bindings, (list, tuple)) or not 1 <= len(bindings) <= 16:
            raise GatewayError("REQUEST_INVALID", "bounded saved group binding required")
        frozen, seen = [], set()
        for binding in bindings:
            if not isinstance(binding, dict):
                raise GatewayError("REQUEST_INVALID", "invalid child binding")
            key, schema = binding.get("child_key"), binding.get("output_schema")
            if (not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None or key in seen
                    or not isinstance(schema, str) or not schema.startswith("schema://")
                    or len(schema.encode("utf-8")) > 256 or any(c in schema for c in "*\x00\r\n\t ")):
                raise GatewayError("REQUEST_INVALID", "invalid or duplicate child binding")
            seen.add(key)
            frozen.append((key, schema))
        result = await self._post("/internal/agent/gather", {"operation_key": operation_key}, timeout)
        group, run_id = result.get("group"), getattr(self._context, "task_id", "")
        if (not isinstance(group, dict) or group.get("version") != "agent-group-result/v1" or not run_id
                or group.get("parent_run_id") != run_id or group.get("operation_key") != operation_key
                or group.get("instruction_trust") != "untrusted_data" or type(group.get("terminal")) is not bool
                or type(group.get("outputs_complete")) is not bool or not isinstance(group.get("children"), list)
                or len(group["children"]) != len(frozen)
                or any(type(group.get(key)) is not int or not 0 <= group[key] <= len(frozen)
                       for key in ("completed", "failed", "cancelled", "pending", "outputs_omitted"))):
            raise GatewayError("AGENT_GROUP_REJECTED", "group does not match current plan")
        try:
            if len(json.dumps(result, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")) > 524288:
                raise ValueError("oversized group")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise GatewayError("AGENT_GROUP_REJECTED", "group must be bounded JSON") from exc
        counts = {key: 0 for key in ("completed", "failed", "cancelled", "pending", "outputs_omitted")}
        uncertain = False
        for ordinal, child in enumerate(group["children"]):
            try:
                self._validate_agent_child_result({"child": child}, run_id, operation_key, ordinal, *frozen[ordinal])
            except GatewayError as exc:
                raise GatewayError("AGENT_GROUP_REJECTED", "group contains an invalid child") from exc
            state = child["status"]
            counts[state if state in ("completed", "failed", "cancelled") else "pending"] += 1
            counts["outputs_omitted"] += int(child["output_omitted"])
            uncertain = uncertain or state == "uncertain"
        terminal = counts["pending"] == 0
        state = "uncertain" if uncertain else "in_progress" if not terminal else "failed" if counts["failed"] else "cancelled" if counts["cancelled"] else "completed"
        complete = terminal and counts["completed"] == len(frozen) and counts["outputs_omitted"] == 0
        if group.get("status") != state or group["terminal"] != terminal or group["outputs_complete"] != complete or any(group[key] != value for key, value in counts.items()):
            raise GatewayError("AGENT_GROUP_REJECTED", "group summary contradicts its children")
        return result

    async def run_harness(self, input: dict, *, key: str, max_rounds: int = 4,
                          max_tool_calls: int = 8, confirmation_token: str = "",
                          timeout: float = 30, action_validator=None, progress_evaluator=None,
                          extension_id: str = "", deadline_ms: int | None = None) -> dict:
        """Persist loop state through governed APIs; never replay unknown effects."""
        from .harness import run_harness
        return await run_harness(self, input, key=key, max_rounds=max_rounds,
                                 max_tool_calls=max_tool_calls,
                                 confirmation_token=confirmation_token, timeout=timeout,
                                 action_validator=action_validator, progress_evaluator=progress_evaluator,
                                 extension_id=extension_id, deadline_ms=deadline_ms)

    async def run_step_workflow(self, steps, executor, **configuration) -> dict:
        """Execute an ordered plan using durable governed operation adapters."""
        from .step_workflow import run_step_workflow
        return await run_step_workflow(self, steps, executor, **configuration)

    async def load_harness_policy(self, timeout: float = 10) -> dict:
        """Read the current server-governed Harness limits for this execution."""
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid policy request timeout")
        result = await self._post("/internal/runtime/harness-policy", {}, timeout)
        return self._validate_harness_policy_response(result)

    @staticmethod
    def _validate_harness_policy_response(result):
        if (not isinstance(result, dict) or set(result) != {"version", "policy_hash", "server_time_ms", "limits"}
                or result.get("version") != "harness-policy/v1"):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid Harness policy response")
        policy_hash = result.get("policy_hash")
        server_time_ms = result.get("server_time_ms")
        limits = result.get("limits")
        if (not isinstance(policy_hash, str) or re.fullmatch(r"[0-9a-f]{64}", policy_hash) is None
                or type(server_time_ms) is not int or not 0 < server_time_ms <= (1 << 53) - 1
                or not isinstance(limits, dict)
                or set(limits) != {"max_rounds", "max_tool_calls", "max_repeated_calls",
                                   "max_elapsed_seconds", "limit_behavior"}
                or type(limits.get("max_rounds")) is not int or not 1 <= limits["max_rounds"] <= 8
                or type(limits.get("max_tool_calls")) is not int or not 1 <= limits["max_tool_calls"] <= 16
                or type(limits.get("max_repeated_calls")) is not int or not 1 <= limits["max_repeated_calls"] <= 4
                or type(limits.get("max_elapsed_seconds")) is not int or not 10 <= limits["max_elapsed_seconds"] <= 3600
                or limits.get("limit_behavior") not in ("error", "incomplete")):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid Harness policy fields")
        deadline = server_time_ms + limits["max_elapsed_seconds"] * 1000
        if deadline > (1 << 53) - 1:
            raise GatewayError("HARNESS_POLICY_REJECTED", "Harness deadline is outside the exact range")
        return {"version": result["version"], "policy_hash": policy_hash,
                "server_time_ms": server_time_ms, "limits": dict(limits)}

    async def resolve_prompt(self, timeout: float = 10) -> dict:
        return await self._post("/internal/prompt/resolve", {}, timeout)

    async def load_execution_policy(self, timeout: float = 10) -> dict:
        """Opt in to v2 batch bounds without changing the v1 response contract."""
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid policy request timeout")
        result = await self._post("/internal/runtime/harness-policy", {"include_batch": True}, timeout)
        if (not isinstance(result, dict) or set(result) != {"version", "policy_hash", "server_time_ms", "limits", "execution"}
                or result.get("version") != "harness-policy/v2"
                or not isinstance(result.get("policy_hash"), str) or re.fullmatch(r"[0-9a-f]{64}", result["policy_hash"]) is None
                or type(result.get("server_time_ms")) is not int or not 0 < result["server_time_ms"] <= (1 << 53) - 1):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid execution policy response")
        execution = result["execution"]
        if (not isinstance(execution, dict) or set(execution) not in
                ({"task_timeout_seconds", "batch"}, {"task_timeout_seconds", "batch", "window"})
                or type(execution["task_timeout_seconds"]) is not int or execution["task_timeout_seconds"] < 1):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid execution limits")
        batch = execution["batch"]
        if batch is not None and (not isinstance(batch, dict)
                or set(batch) != {"max_items", "item_timeout_seconds", "elapsed_seconds"}
                or any(type(value) is not int for value in batch.values())
                or not 1 <= batch["max_items"] <= 10000
                or not 1 <= batch["item_timeout_seconds"] <= batch["elapsed_seconds"] <= 3600
                or batch["elapsed_seconds"] != execution["task_timeout_seconds"]):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid batch profile")
        self._validate_harness_policy_response({"version": "harness-policy/v1", **{
            key: result[key] for key in ("policy_hash", "server_time_ms", "limits")}})
        window = execution.get("window")
        if batch is not None and (not isinstance(window, dict) or set(window) != {"started_ms", "deadline_ms"}
                or any(type(value) is not int or not 0 < value <= (1 << 53) - 1 for value in window.values())
                or window["started_ms"] > result["server_time_ms"]
                or window["deadline_ms"] != window["started_ms"] + batch["elapsed_seconds"] * 1000):
            raise GatewayError("HARNESS_POLICY_REJECTED", "invalid original execution window")
        if batch is None and window is not None:
            raise GatewayError("HARNESS_POLICY_REJECTED", "unexpected execution window")
        return result

    async def invoke_tool(self, name: str, payload: dict, confirmed: bool = False, timeout: float = 30,
                          *, call_id: str | None = None, confirmation_token: str = "") -> dict:
        """Governed tool call using this execution's signed/renewable context.

        Retry only an explicit invoke-in-progress response with the same call
        ID. Transport loss may read one original receipt within the original
        budget; it never repeats an unknown invocation or denied permission.
        """
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or not isinstance(payload, dict):
            raise ValueError("tool name and object payload required")
        if (not isinstance(confirmation_token, str) or len(confirmation_token.encode("utf-8")) > 8192
                or (call_id is not None and (not isinstance(call_id, str) or not call_id.strip()
                                            or len(call_id.encode("utf-8")) > 128))
                or (confirmation_token and call_id is None)):
            raise ValueError("confirmation requires the exact approved call ID and a bounded token")
        identity = {"name": name, "payload": payload, "confirmed": confirmed}
        identity["call_id"] = call_id if call_id is not None else self._idempotency_key("tool-", identity)
        if confirmation_token:
            identity["confirmation_token"] = confirmation_token
        for attempt in range(5):
            try:
                return await self._post("/internal/tool/invoke", identity, timeout)
            except GatewayError as exc:
                if exc.code != "TOOL_INVOCATION_IN_PROGRESS" or attempt == 4:
                    raise
                await asyncio.sleep(0.05 * 2**attempt)
        raise AssertionError("bounded tool receipt polling exhausted")

    async def prepare_context(
        self, messages: list[dict], function_names: list[str] | None = None,
        timeout: float = 30,
    ) -> dict:
        """Use the approved system prompt, window and untrusted-summary policy.

        Preparation performs no model call. The returned transcript can be
        sent through the normal governed model API with a stable step key.
        """
        return await self._post("/internal/context/prepare", {
            "messages": messages, "function_names": function_names or [],
        }, timeout)

    async def load_skill(self, skill_id: str, section: str = "", timeout: float = 30) -> dict:
        """Disclose summary or one section of the current run-pinned Skill.

        Loading grants no tools or resources. Lifecycle administration uses
        the separate human control plane.
        """
        if (not isinstance(skill_id, str) or not skill_id or len(skill_id.encode()) > 128
                or not isinstance(section, str) or len(section.encode()) > 128):
            raise ValueError("valid skill and optional section required")
        return await self._post("/internal/skill/load", {
            "skill_id": skill_id, "section": section,
        }, timeout)

    async def load_checkpoint(
        self, namespace: str, key: str, schema_id: str, revision: int = 0,
        timeout: float = 30,
    ) -> dict:
        """Read run-scoped public state under the current execution authority."""
        from .checkpoint_capacity import revision_limit, remember
        if type(revision) is not int or not 0 <= revision <= revision_limit(self):
            raise ValueError("checkpoint revision exceeds the published negotiated capacity")
        from .graph_state_fence import load as fenced_graph_load
        fenced = await fenced_graph_load(self, namespace, key, schema_id, revision, timeout)
        if fenced is not None:
            return fenced
        result = await self._post("/internal/state/checkpoint", {
            "operation": "load", "namespace": namespace, "key": key,
            "schema_id": schema_id, "revision": revision,
        }, timeout)
        remember(self, result)
        from .recovery_context import validate_runtime_recovery_checkpoint
        validate_runtime_recovery_checkpoint(namespace, key, schema_id, result)
        return result

    async def load_recovery_checkpoint(self, reference: dict, timeout: float = 30) -> dict:
        """Read and verify a captured current head under live platform authority.

        This does not authorize execution, renew state, or complete SDK recovery.
        Invalid, stale, foreign or expired references propagate platform errors.
        """
        fields = {"state_key", "revision", "schema_id", "content_hash",
                  "execution_revision", "expires_at"}
        if not isinstance(reference, dict) or set(reference) != fields:
            raise ValueError("exact recovery checkpoint reference required")
        try:
            raw = json.dumps(reference, ensure_ascii=False, separators=(",", ":"),
                             allow_nan=False).encode("utf-8")
            if len(raw) > 4096:
                raise ValueError("recovery checkpoint reference exceeds limit")
            snapshot = json.loads(raw)
        except (TypeError, ValueError, OverflowError, RecursionError) as exc:
            raise ValueError("bounded JSON recovery reference required") from exc
        result = await self._post("/internal/state/checkpoint", {
            "operation": "load", "reference": snapshot,
        }, timeout)
        from .checkpoint_capacity import remember
        return remember(self, result)

    async def save_checkpoint(
        self, namespace: str, key: str, schema_id: str, value: dict,
        expected_revision: int, idempotency_key: str, timeout: float = 30,
    ) -> dict:
        """CAS write; the platform controls scope, generation, TTL and quota.

        Reuse the same operation key for a replay. Revision conflicts and
        uncertain transport results are returned without automatic retries.
        """
        from .checkpoint_capacity import revision_limit, remember
        if (type(expected_revision) is not int or not 0 <= expected_revision < revision_limit(self)
                or not isinstance(value, dict) or not isinstance(idempotency_key, str)
                or not idempotency_key):
            raise ValueError("checkpoint CAS, object and operation key are required")
        from .graph_state_fence import before_save as graph_before_save
        graph_before_save(namespace, key, schema_id, expected_revision)
        result = await self._post("/internal/state/checkpoint", {
            "operation": "save", "namespace": namespace, "key": key,
            "schema_id": schema_id, "value": value,
            "expected_revision": expected_revision, "idempotency_key": idempotency_key,
        }, timeout)
        remember(self, result)
        from .recovery_context import record_runtime_recovery_checkpoint_save
        from .graph_state_fence import saved as graph_state_saved
        graph_state_saved(namespace, key, schema_id, expected_revision, result)
        record_runtime_recovery_checkpoint_save(namespace, key, schema_id,
                                                expected_revision, result)
        return result

    async def search_knowledge(
        self,
        query: str,
        scope: str,
        top_k: int = 3,
        timeout: float = 30,
        as_of: str = "",
        cache_mode: str = "",
        source_ids: list[str] | None = None,
        *, recovery_only: bool = False,
    ) -> dict:
        if cache_mode not in ("", "use", "cold", "bypass"):
            raise ValueError("cache_mode must be use, cold or bypass")
        if type(recovery_only) is not bool:
            raise ValueError("recovery_only requires a boolean")
        identity = {
            "query": query,
            "knowledge_scope": scope,
            "top_k": top_k,
            "as_of": as_of,
        }
        if cache_mode:
            identity["cache_mode"] = cache_mode
        if source_ids is not None:
            if (not isinstance(source_ids, list) or not source_ids or len(source_ids) > 16
                    or any(not isinstance(s, str) or not s or s.strip() != s or len(s) > 128 for s in source_ids)
                    or len(set(source_ids)) != len(source_ids)):
                raise ValueError("source_ids requires unique nonempty provider IDs")
            identity["source_ids"] = list(source_ids)
        identity["idempotency_key"] = self._idempotency_key("knowledge-", identity)
        path = "/internal/knowledge/search/recovery" if recovery_only else "/internal/knowledge/search"
        return await self._post(path, identity, timeout)

    async def run_knowledge_search(self, query: str, scope: str, *, key: str, as_of: str,
                                   top_k: int = 5, cache_mode: str = "use", timeout: float = 30,
                                   recovery_only: bool = False, source_ids: list[str] | None = None) -> dict:
        """Durable search with explicit business date and read-only recovery."""
        from .knowledge_search import run_knowledge_search
        return await run_knowledge_search(self, query, scope, key=key, as_of=as_of,
                                         top_k=top_k, cache_mode=cache_mode, timeout=timeout,
                                         recovery_only=recovery_only, source_ids=source_ids)

    async def load_skill_bindings(self, skill_ids: list[str], timeout: float = 30) -> dict:
        """Load approved summaries and return metadata for public RAG requests.

        The platform owns pin selection and current authorization. These bindings
        are not permission caches and must be rechecked at each model/cache edge.
        """
        from .harness import _skill_identifier
        if (not isinstance(skill_ids, list) or not 1 <= len(skill_ids) <= 4
                or any(not _skill_identifier(value) for value in skill_ids) or len(set(skill_ids)) != len(skill_ids)):
            raise GatewayError("HARNESS_SKILL_REJECTED", "valid skill identifiers required")
        bindings = {}
        for skill_id in skill_ids:
            receipt = await self.load_skill(skill_id, "", timeout=timeout)
            value = receipt.get("skill")
            if (not isinstance(value, dict) or value.get("version") != "skill-disclosure/v1"
                    or value.get("skill_id") != skill_id or value.get("instruction_trust") != "untrusted_data"
                    or not _skill_identifier(value.get("version_id")) or not isinstance(value.get("digest"), str)):
                raise GatewayError("HARNESS_SKILL_REJECTED", "approved skill summary required")
            try:
                if len(value["digest"]) != 64 or bytes.fromhex(value["digest"]).hex() != value["digest"]:
                    raise ValueError()
            except ValueError:
                raise GatewayError("HARNESS_SKILL_REJECTED", "approved skill digest required")
            bindings[skill_id] = {"version_id": value["version_id"], "digest": value["digest"]}
        return bindings

    async def run_knowledge_harness(self, query: str, scope: str, *, key: str, top_k: int = 3, cache_mode: str = "use", skill_requests: list[dict] | None = None, timeout: float = DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS, as_of: str = "", source_ids: list[str] | None = None) -> dict:
        """Checkpointed public RAG; recovery never sends replacement model calls."""
        from .knowledge_harness import run_knowledge_harness
        return await run_knowledge_harness(self, query, scope, key=key, top_k=top_k,
            cache_mode=cache_mode, skill_requests=skill_requests, timeout=timeout, as_of=as_of, source_ids=source_ids)

    async def answer_knowledge(
        self,
        query: str,
        scope: str,
        top_k: int = 3,
        cache_mode: str = "use",
        timeout: float = DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS,
        *, skill_requests: list[dict] | None = None, skill_bindings: dict | None = None, recovery_only: bool = False, as_of: str = "", source_ids: list[str] | None = None,
    ) -> dict:
        """Reuse the platform RAG pipeline, cited answer and governed cache.

        Requires current caller/workload knowledge and model permissions.
        Evaluation fields are evidence for independent scoring, not a model's
        self-declared correctness. A cache hit reports zero new model usage.
        """
        if type(recovery_only) is not bool or cache_mode not in ("use", "cold", "bypass"):
            raise ValueError("cache_mode must be use, cold or bypass")
        identity = {
            "query": query,
            "knowledge_scope": scope,
            "top_k": top_k,
            "cache_mode": cache_mode,
        }
        if as_of:
            from datetime import date
            try:
                if not isinstance(as_of,str) or date.fromisoformat(as_of).isoformat()!=as_of: raise ValueError()
            except (ValueError,TypeError): raise ValueError("invalid knowledge date") from None
            identity["as_of"]=as_of
        if source_ids is not None:
            from .harness import _skill_identifier
            if (not isinstance(source_ids,list) or not 1<=len(source_ids)<=16 or any(not _skill_identifier(v) for v in source_ids) or len(set(source_ids))!=len(source_ids)):
                raise ValueError("invalid knowledge sources")
            identity["source_ids"]=list(source_ids)
        if skill_requests is not None or skill_bindings is not None:
            from .harness import _skill_identifier
            if (not isinstance(skill_requests, list) or not 1 <= len(skill_requests) <= 4
                    or not isinstance(skill_bindings, dict) or len(skill_bindings) != len(skill_requests)):
                raise GatewayError("HARNESS_SKILL_REJECTED", "valid pinned knowledge skills required")
            seen = set()
            for selection in skill_requests:
                if (not isinstance(selection, dict) or set(selection) - {"skill_id", "sections"}
                        or not _skill_identifier(selection.get("skill_id")) or selection["skill_id"] in seen):
                    raise GatewayError("HARNESS_SKILL_REJECTED", "valid pinned knowledge skills required")
                seen.add(selection["skill_id"])
                sections = selection.get("sections", [])
                binding = skill_bindings.get(selection["skill_id"])
                if (not isinstance(sections, list) or len(sections) > 4
                        or any(not _skill_identifier(section) for section in sections) or len(set(sections)) != len(sections)
                        or not isinstance(binding, dict) or set(binding) != {"version_id", "digest"}
                        or not _skill_identifier(binding.get("version_id")) or not isinstance(binding.get("digest"), str)):
                    raise GatewayError("HARNESS_SKILL_REJECTED", "valid pinned knowledge skills required")
                try:
                    if len(binding["digest"]) != 64 or bytes.fromhex(binding["digest"]).hex() != binding["digest"]:
                        raise ValueError()
                except ValueError:
                    raise GatewayError("HARNESS_SKILL_REJECTED", "valid pinned knowledge skills required")
            # Detach orchestration metadata before hashing or sending it.
            identity["skill_requests"] = json.loads(json.dumps(skill_requests, ensure_ascii=False, allow_nan=False))
            identity["skill_bindings"] = json.loads(json.dumps(skill_bindings, ensure_ascii=False, allow_nan=False))
        identity["idempotency_key"] = self._idempotency_key("knowledge-answer-", identity)
        path = "/internal/knowledge/answer/recovery" if recovery_only else "/internal/knowledge/answer"
        return await self._post(path, identity, timeout)

    async def replay_knowledge(self, request_id: str, timeout: float = 30) -> dict:
        return await self._post(
            "/internal/knowledge/replay", {"request_id": request_id}, timeout
        )

    async def memory_load(
        self, namespace: str, key: str, timeout: float = 10
    ) -> dict | None:
        data = await self._post(
            "/internal/memory/access",
            {"operation": "load", "namespace": namespace, "key": key},
            timeout,
        )
        value = data.get("value")
        return value if isinstance(value, dict) else None

    async def memory_save(
        self, namespace: str, key: str, value: dict, timeout: float = 10
    ) -> None:
        await self._post(
            "/internal/memory/access",
            {"operation": "save", "namespace": namespace, "key": key, "value": value},
            timeout,
        )

    async def load(self, namespace: str, key: str) -> dict | None:
        return await self.memory_load(namespace, key)

    async def save(self, namespace: str, key: str, value: dict) -> None:
        await self.memory_save(namespace, key, value)
