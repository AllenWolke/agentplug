"""Durable public RAG boundary; recovery reads existing model receipts only."""

import hashlib
import json
import re

from .capability_client import GatewayError
from .harness import _skill_identifier
from .recovery_context import (authorize_runtime_recovery_start, complete_runtime_recovery_step,
    record_runtime_recovery_checkpoint_save, validate_runtime_recovery_checkpoint)

STATE_SCHEMA = "schema://agentplug/knowledge-harness/v1"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


async def run_knowledge_harness(client, query, scope, *, key, top_k=3, cache_mode="use", skill_requests=None, timeout=310):
    """Pin approved Skill dependencies and persist the provider-send boundary.

    First entry uses the normal public pipeline. Every recovery/finished replay
    uses its read-only route, never a replacement call. Results are freshly
    reauthorized; they are not stored in checkpoints as a disclosure shortcut.
    A missing, changed or unknown receipt stops for governed reconciliation.
    This composes RAG with State/Skill/model receipts without an extra LLM call.
    """
    if (not isinstance(key, str) or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", key) is None
            or not isinstance(query, str) or not query.strip() or len(query.encode()) > 8192
            or not _skill_identifier(scope) or type(top_k) is not int or not 1 <= top_k <= 5
            or cache_mode not in ("use", "cold", "bypass") or not isinstance(skill_requests, list)
            or not 1 <= len(skill_requests) <= 4):
        raise GatewayError("REQUEST_INVALID", "bounded pinned knowledge workflow required")
    try:
        requests = json.loads(_json(skill_requests))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise GatewayError("REQUEST_INVALID", "invalid knowledge skills") from exc
    ids = []
    for request in requests:
        if (not isinstance(request, dict) or set(request) - {"skill_id", "sections"}
                or not _skill_identifier(request.get("skill_id")) or request["skill_id"] in ids
                or not isinstance(request.get("sections", []), list) or len(request.get("sections", [])) > 4
                or any(not _skill_identifier(section) for section in request.get("sections", []))
                or len(set(request.get("sections", []))) != len(request.get("sections", []))):
            raise GatewayError("HARNESS_SKILL_REJECTED", "invalid pinned knowledge skill selection")
        ids.append(request["skill_id"])
    digest = hashlib.sha256(_json([query, scope, top_k, cache_mode, requests]).encode()).hexdigest()
    parent = getattr(client._context, "task_id", "")
    if not parent:
        raise GatewayError("HARNESS_STATE_REJECTED", "verified run required")
    loaded = await client.load_checkpoint("knowledge-harness", key, STATE_SCHEMA, timeout=timeout)
    validate_runtime_recovery_checkpoint("knowledge-harness", key, STATE_SCHEMA, loaded)
    checkpoint = loaded.get("checkpoint")
    if checkpoint is None:
        authorize_runtime_recovery_start("knowledge-harness", key, STATE_SCHEMA, digest)
    # Resolving current disclosures is read-only. Never silently change a pin.
    bindings = await client.load_skill_bindings(ids, timeout=timeout)
    revision = 0
    state = {"version": "knowledge-harness/v1", "parent_run_id": parent, "input_hash": digest,
             "phase": "answer_dispatch", "skill_bindings": bindings}
    if checkpoint is not None:
        previous = checkpoint.get("value") if isinstance(checkpoint, dict) else None
        if (not isinstance(checkpoint, dict) or type(checkpoint.get("revision")) is not int
                or not 1 <= checkpoint["revision"] <= 2 or not isinstance(previous, dict)
                or previous.get("version") != state["version"] or previous.get("parent_run_id") != parent
                or previous.get("input_hash") != digest or previous.get("phase") not in ("answer_dispatch", "completed")
                or previous.get("skill_bindings") != bindings
                or (checkpoint["revision"] == 1 and previous.get("phase") != "answer_dispatch")
                or (checkpoint["revision"] == 2 and previous.get("phase") != "completed")):
            raise GatewayError("HARNESS_STATE_REJECTED", "knowledge state or pinned dependency changed")
        revision, state = checkpoint["revision"], json.loads(_json(previous))

    async def save():
        nonlocal revision
        result = await client.save_checkpoint("knowledge-harness", key, STATE_SCHEMA,
            json.loads(_json(state)), revision, f"knowledge-{revision + 1}", timeout=timeout)
        record_runtime_recovery_checkpoint_save("knowledge-harness", key, STATE_SCHEMA, revision, result)
        saved = result.get("checkpoint")
        if (not isinstance(saved, dict) or type(saved.get("revision")) is not int or saved["revision"] != revision + 1):
            raise GatewayError("HARNESS_STATE_REJECTED", "knowledge checkpoint receipt rejected")
        revision += 1

    recovering = revision != 0
    if not recovering:
        # Persist before provider-capable RAG dispatch. Lost save replies stop.
        await save()
    result = await client.answer_knowledge(query, scope, top_k=top_k, cache_mode=cache_mode,
        skill_requests=requests, skill_bindings=state["skill_bindings"],
        recovery_only=recovering, timeout=timeout)
    if (not isinstance(result, dict) or not isinstance(result.get("text"), str) or not result["text"].strip()
            or len(result["text"].encode()) > 32768 or not isinstance(result.get("references"), list) or not result["references"]
            or not isinstance(result.get("citation_ids"), list) or not result["citation_ids"]):
        raise GatewayError("KNOWLEDGE_RESPONSE_INVALID", "current cited platform answer required")
    if state["phase"] != "completed":
        state["phase"] = "completed"
        await save()
    await complete_runtime_recovery_step("knowledge-harness", key, STATE_SCHEMA)
    return result
