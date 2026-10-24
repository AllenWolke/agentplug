"""Exact captured State heads for dynamically named durable graph children.

This is SDK orchestration authority, never a business checkpoint permission.
The platform verifies each reference under the current signed execution lease.
New state is allowed only after a live scoped absence check. Existing uncaptured
state, schema changes and historical revisions fail before business execution.
"""
from __future__ import annotations
import copy
from contextvars import ContextVar
from dataclasses import dataclass, field

from .capability_client import GatewayError
from .recovery_context import checkpoint_state_key


@dataclass
class Fence:
    scope: object
    references: dict[str, dict]
    heads: dict[str, dict] = field(default_factory=dict)
    absent: set[str] = field(default_factory=set)
    active: bool = True


_current = ContextVar("graph_exact_state_heads", default=None)


def deny():
    return GatewayError("RECOVERY_STATE_UNAVAILABLE", "captured graph state is unavailable")


def bind(scope, references):
    value = Fence(scope, {ref["state_key"]: copy.deepcopy(ref) for ref in references})
    return value, _current.set(value)


def close(value, token):
    value.active = False
    _current.reset(token)


async def load(client, namespace, key, schema, revision, timeout):
    fence = _current.get()
    if fence is None:
        return None
    if not fence.active or revision != 0:
        raise deny()
    identity = checkpoint_state_key(fence.scope, namespace, key)
    reference = fence.heads.get(identity) or fence.references.get(identity)
    if reference is not None:
        if reference["schema_id"] != schema:
            raise deny()
        result = await client.load_recovery_checkpoint(reference, timeout=timeout)
        from .execution_lifecycle import ExecutionLifecycle
        ExecutionLifecycle._verify_recovery_checkpoint_response(reference, result)
        fence.heads[identity] = copy.deepcopy(reference)
        return result
    result = await client._post("/internal/state/checkpoint", {"operation": "load", "namespace": namespace,
        "key": key, "schema_id": schema, "revision": 0}, timeout)
    if not isinstance(result, dict) or result.get("checkpoint") is not None:
        raise deny()
    fence.absent.add(identity)
    return result


def before_save(namespace, key, schema, expected):
    fence = _current.get()
    if fence is None:
        return
    if not fence.active:
        raise deny()
    identity = checkpoint_state_key(fence.scope, namespace, key)
    previous = fence.heads.get(identity) or fence.references.get(identity)
    if ((previous is None and (identity not in fence.absent or expected != 0))
            or (previous is not None and (previous["schema_id"] != schema or previous["revision"] != expected))):
        raise deny()
    return fence, identity


def saved(namespace, key, schema, expected, receipt):
    checked = before_save(namespace, key, schema, expected)
    if checked is None:
        return
    fence, identity = checked
    checkpoint = receipt.get("checkpoint", {})
    fields = ("revision", "schema_id", "content_hash", "execution_revision", "expires_at")
    if any(name not in checkpoint for name in fields) or checkpoint["schema_id"] != schema or checkpoint["revision"] != expected + 1:
        raise deny()
    reference = {name: checkpoint[name] for name in fields}
    reference["state_key"] = identity
    from .execution_lifecycle import ExecutionLifecycle
    ExecutionLifecycle._verify_recovery_checkpoint_response(reference, {"state_key": identity, **receipt})
    fence.heads[identity] = reference
