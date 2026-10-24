"""Durable retrieval; recover internal rewrite/embed/rerank receipts only."""
from __future__ import annotations

from datetime import date
import hashlib
import json
import math
import re

from .capability_client import GatewayError
from .recovery_context import (
    authorize_runtime_recovery_start, complete_runtime_recovery_step,
    record_runtime_recovery_checkpoint_save, validate_runtime_recovery_checkpoint,
)

STATE_SCHEMA = "schema://agentplug/knowledge-search/v1"
NAMESPACE = "knowledge-search"


def _stop(code):
    return GatewayError(code, "durable knowledge search stopped at a governed boundary")


async def run_knowledge_search(client, query, scope, *, key, as_of, top_k=5,
                               cache_mode="use", timeout=30, recovery_only=False, source_ids=None):
    if (not isinstance(query, str) or not query.strip() or len(query.encode()) > 8192
            or not isinstance(scope, str) or not scope or len(scope.encode()) > 128
            or not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key) is None
            or not isinstance(as_of, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", as_of) is None
            or type(top_k) is not int or not 1 <= top_k <= 20 or type(recovery_only) is not bool
            or cache_mode not in {"use", "cold", "bypass"}
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0):
        raise _stop("KNOWLEDGE_SEARCH_CONFIG_INVALID")
    if source_ids is not None and (not isinstance(source_ids, list) or not 1 <= len(source_ids) <= 16
            or any(not isinstance(value, str) or not value or value.strip() != value
                   or len(value) > 128 for value in source_ids)
            or len(set(source_ids)) != len(source_ids)):
        raise _stop("KNOWLEDGE_SEARCH_CONFIG_INVALID")
    try:
        date.fromisoformat(as_of)
    except ValueError:
        raise _stop("KNOWLEDGE_SEARCH_CONFIG_INVALID") from None
    digest = hashlib.sha256(json.dumps([query, scope, as_of, top_k, cache_mode, source_ids],
                                      ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    loaded = await client.load_checkpoint(NAMESPACE, key, STATE_SCHEMA, timeout=timeout)
    validate_runtime_recovery_checkpoint(NAMESPACE, key, STATE_SCHEMA, loaded)
    checkpoint, revision = loaded.get("checkpoint"), 0
    state = {"version": "knowledge-search/v1", "input_hash": digest, "phase": "dispatch"}
    if checkpoint is None:
        if recovery_only:
            # A parent dispatch marker alone cannot prove this child was never
            # sent. Missing child state is unknown, never a fresh search.
            raise _stop("KNOWLEDGE_RECONCILIATION_REQUIRED")
        authorize_runtime_recovery_start(NAMESPACE, key, STATE_SCHEMA, digest)
    else:
        revision, previous = checkpoint.get("revision"), checkpoint.get("value")
        if (type(revision) is not int or revision not in (1, 2) or not isinstance(previous, dict)
                or previous.get("version") != state["version"] or previous.get("input_hash") != digest
                or previous.get("phase") != ("dispatch" if revision == 1 else "completed")):
            raise _stop("KNOWLEDGE_SEARCH_STATE_REJECTED")
        state = previous

    async def save():
        nonlocal revision
        result = await client.save_checkpoint(NAMESPACE, key, STATE_SCHEMA, dict(state), revision,
                                              f"search-{revision + 1}", timeout=timeout)
        record_runtime_recovery_checkpoint_save(NAMESPACE, key, STATE_SCHEMA, revision, result)
        if result.get("checkpoint", {}).get("revision") != revision + 1:
            raise _stop("KNOWLEDGE_SEARCH_STATE_REJECTED")
        revision += 1

    recovering = revision != 0
    if not recovering:
        await save()
    result = await client.search_knowledge(query, scope, top_k=top_k, as_of=as_of,
                                           cache_mode=cache_mode, timeout=timeout,
                                           recovery_only=recovering, source_ids=source_ids)
    if not isinstance(result, dict) or not isinstance(result.get("references"), list):
        raise _stop("KNOWLEDGE_RESPONSE_INVALID")
    if recovering and (result.get("recovery_only") is not True or result.get("model_requests_sent") != 0):
        raise _stop("KNOWLEDGE_RECONCILIATION_REQUIRED")
    # Reference data is freshly authorized on every replay, not disclosed from
    # an old checkpoint. Zero references is a known lack of evidence, not truth.
    if state["phase"] != "completed":
        state["phase"] = "completed"
        await save()
    await complete_runtime_recovery_step(NAMESPACE, key, STATE_SCHEMA)
    return result
