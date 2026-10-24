"""Expand signed metadata pages for large graphs; State values remain lazy.

This is a transport capability for trusted graph adapters. A page, checkpoint
or missing result never authorizes execution or permits an unknown resend.
The legacy inline command is validated by the same lifecycle parser afterward.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re

from .errors import DomainExecutionError

MAXIMUM = 8192
PAGE_SIZE = 64


def deny():
    return DomainExecutionError("RUN_RESUME_UNCONFIRMED")


def digest(references):
    items = [[reference[name] for name in ("state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at")]
             for reference in references]
    encoded = json.dumps(items, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    encoded = (encoded.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")
        .replace("\u2028", r"\u2028").replace("\u2029", r"\u2029"))
    return hashlib.sha256(encoded.encode()).hexdigest()


async def runtime_parts(request, client, identity, generation):
    from .execution_lifecycle import ExecutionLifecycle
    original = request.resume_input or {}
    normalized = copy.deepcopy(original)
    tool_resume = normalized.pop("tool_resume", None)
    if tool_resume is not None:
        if (not isinstance(tool_resume, dict) or set(tool_resume) != {"version", "handoff", "checkpoint"}
                or tool_resume["version"] != "graph-tool-resume/v1" or not original.get("confirmation_token")):
            raise deny()
    if original.get("version") == "runtime-recovery/v1":
        return ExecutionLifecycle._runtime_recovery_reference(request, identity, generation, normalized)
    async def fetch(group,offset,limit):
        return await client._post("/internal/state/checkpoint",{"operation":"load","reference_set":group,"offset":offset,"limit":limit},10)
    expanded = await expand_reference_set(normalized,fetch)
    # Only this digest-verified expansion may use the larger parser bound.
    # Business request and signed identity remain the original v2 envelope.
    return ExecutionLifecycle._runtime_recovery_reference(request, identity, generation, expanded,
        maximum_checkpoints=MAXIMUM)


async def expand_reference_set(original,fetch):
    """Validate immutable metadata pages before enlarging the parser bound."""
    normalized=copy.deepcopy(original)
    reference = original.get("reference")
    if (original.get("version") != "runtime-recovery/v2" or "group_resume" in original
            or not isinstance(reference, dict) or "checkpoints" in reference
            or reference.get("version") != "runtime-recovery-stop/v2"):
        raise deny()
    group = reference.get("checkpoint_set")
    if (not isinstance(group, dict) or set(group) != {"version", "count", "digest"}
            or group["version"] != "recovery-checkpoint-set/v1" or type(group["count"]) is not int
            or not 128 < group["count"] <= MAXIMUM or not isinstance(group["digest"], str)
            or re.fullmatch(r"[a-f0-9]{64}", group["digest"]) is None):
        raise deny()
    references = []
    fields = {"state_key", "revision", "schema_id", "content_hash", "execution_revision", "expires_at"}
    while len(references) < group["count"]:
        offset = len(references)
        page = await fetch(group, offset, PAGE_SIZE)
        if (not isinstance(page, dict) or set(page) != {"version", "set", "offset", "references"}
                or page["version"] != "recovery-checkpoint-page/v1" or page["set"] != group
                or type(page["offset"]) is not int or page["offset"] != offset
                or not isinstance(page["references"], list)
                or len(page["references"]) != min(PAGE_SIZE, group["count"] - offset)
                or any(not isinstance(item, dict) or set(item) != fields for item in page["references"])):
            raise deny()
        references.extend(copy.deepcopy(page["references"]))
    try:
        if digest(references) != group["digest"]:
            raise deny()
    except (KeyError, TypeError, ValueError):
        raise deny() from None
    expanded = normalized
    expanded["version"] = "runtime-recovery/v1"
    expanded["reference"]["version"] = "runtime-recovery-stop/v1"
    del expanded["reference"]["checkpoint_set"]
    expanded["reference"]["checkpoints"] = references
    return expanded
