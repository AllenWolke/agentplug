"""A receipt-aware facade for existing chat/search application ports."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time

from .capability_client import DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS, GatewayError
from .model_usage import chat_usage


class DurableStageClient:
    """Use existing Harness and search workflows, without new provider clients.

    Only a trusted adapter creates this facade. Stable business keys bind each
    stage; model and knowledge gateways still enforce published policies.
    """
    def __init__(self, client, *, key: str, deadline_ms: int):
        self.client, self.key, self.deadline_ms = client, key, deadline_ms
        self.receipts: dict[str, dict] = {}

    def _key(self, kind: str, identity) -> str:
        digest = hashlib.sha256(json.dumps([self.key, kind, identity], ensure_ascii=False,
                                           sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        return "stage-" + digest

    def _timeout(self, timeout):
        remaining = (self.deadline_ms - int(time.time() * 1000)) / 1000
        # Receipt recovery remains available after the deadline. Harness itself
        # refuses fresh sends; knowledge callers must only enter a fresh search
        # after checking their parent's remaining budget.
        return min(timeout, max(0.001, remaining))

    async def resolve_prompt(self, timeout=10):
        return await self.client.resolve_prompt(timeout=timeout)

    async def chat(self, messages, temperature=0.3, max_tokens=2048,
                   timeout=DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS,
                   step_name="model.generate", *, require_json=False, response_schema=None, response_schema_mode=""):
        if type(require_json) is not bool:
            raise ValueError("require_json must be a boolean")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('invalid model observation timeout')
        identity = [step_name, messages, temperature, max_tokens]
        if require_json:
            identity.append({"require_json": True})
        from .response_schema import schema_request
        schema, mode = schema_request(response_schema, response_schema_mode, require_json)
        if schema is not None:
            identity.append({"response_schema": schema, "response_schema_mode": mode})
        key = self._key("model", identity)
        request = {"messages": messages, "function_names": [],
            "idempotency_key": key, "temperature": temperature, "max_tokens": max_tokens,
            "usage_step": step_name}
        if require_json:
            request["require_json"] = True
        if schema is not None:
            request.update(response_schema=schema, response_schema_mode=mode)
        # The platform owns physical attempt limits. A hidden 30-second HTTP
        # clamp otherwise races a published 30-second provider attempt and
        # leaves no time to persist its receipt or select an approved alternate.
        # The immutable Harness deadline still prohibits late fresh sends.
        observer_timeout = self._timeout(timeout) if self.deadline_ms > int(time.time() * 1000) else min(timeout, 30)
        result = await self.client.run_harness(request, key=key, max_rounds=1, max_tool_calls=1,
            timeout=observer_timeout, extension_id="single-model-stage/v1", deadline_ms=self.deadline_ms)
        self.receipts[key] = result
        output = result.get("output", {})
        if result.get("status") != "completed" or not isinstance(output.get("text"), str):
            raise GatewayError("MODEL_STAGE_INCOMPLETE", "durable model stage did not complete")
        usage = output.get("usage", {})
        response = {"text": output["text"], "model": output.get("model", ""),
                "usage": chat_usage(usage),
                "execution": result["execution"], "billing": output.get("billing")}
        for field in ("routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id"):
            if field in output:
                response[field] = output[field]
        return response

    async def search_knowledge(self, query, scope, top_k=3,
                               timeout=DEFAULT_GATEWAY_REQUEST_TIMEOUT_SECONDS, as_of="", cache_mode="",
                               source_ids=None, *, recovery_only=False):
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise GatewayError("KNOWLEDGE_SEARCH_CONFIG_INVALID", "invalid observation timeout")
        key = self._key("knowledge", [query, scope, as_of, top_k, cache_mode or "use", source_ids])
        # Do not start an uncheckpointed search after the original deadline.
        if self.deadline_ms <= int(time.time() * 1000):
            recovery_only = True
        # One observation budget covers checkpoint load, dispatch, response and
        # checkpoint save. A slower authorized search can use the parent's
        # remaining time; each HTTP operation cannot restart that budget.
        budget = min(timeout, 30) if recovery_only else self._timeout(timeout)
        try:
            async with asyncio.timeout(budget):
                result = await self.client.run_knowledge_search(query, scope, key=key, as_of=as_of,
                    top_k=top_k, cache_mode=cache_mode or "use", timeout=budget,
                    recovery_only=recovery_only, source_ids=source_ids)
        except TimeoutError as error:
            # A timeout does not establish whether internal model work finished.
            # The existing search checkpoint requires read-only reconciliation
            # on replay; never automatically issue a replacement search here.
            raise GatewayError("UPSTREAM_TIMEOUT", "knowledge observation deadline exceeded") from error
        self.receipts[key] = result
        return result

    async def embed(self, *args, **kwargs):
        # Applications should retrieve through public Knowledge. Direct embed
        # has a separate receipt contract and cannot be silently made durable.
        raise GatewayError("MODEL_STAGE_REJECTED", "use the governed knowledge workflow")
