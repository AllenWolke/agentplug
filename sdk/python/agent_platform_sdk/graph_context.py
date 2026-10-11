"""Transient execution credentials for an already authorized durable graph.

Business checkpoints retain their immutable scope and policy. A resumed graph
uses the live dispatch context for capability calls, without writing a refreshed
credential into a LangGraph LastValue channel or replaying completed nodes.
"""
from __future__ import annotations

import copy
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

_VOLATILE = {"platform_context_token", "execution_revision", "execution_operation"}
_SCOPE = {"actor_id": "principal_id", "task_id": "run_id"}
_FIELDS = ("tenant_id", "department_id", "application_id", "installation_id",
           "agent_instance_id", "agent_id", "agent_version_id", "principal_type",
           "actor_id", "task_id", "parent_run_id", "session_id", "trace_id",
           "authorization_epoch")


def _deny():
    from .errors import DomainExecutionError
    return DomainExecutionError("RUN_RESUME_UNCONFIRMED")


def _immutable(context: Any) -> dict:
    # Include custom policy/configuration fields too; only credentials and the
    # current execution generation may change across a graph resumption.
    values = context.model_dump() if hasattr(context, "model_dump") else vars(context)
    return copy.deepcopy({key: value for key, value in values.items() if key not in _VOLATILE})


@dataclass
class _Binding:
    context: Any
    immutable: dict
    active: bool = True


_current: ContextVar[_Binding | None] = ContextVar("verified_graph_context", default=None)


def bind_graph_context(request, context):
    """Call only after signed transport verification AND live execution validation."""
    if any(getattr(context, field, None) != getattr(request.scope, _SCOPE.get(field, field))
           for field in _FIELDS):
        raise _deny()
    if (getattr(context, "idempotency_key", None) != request.idempotency_key
            or not getattr(context, "platform_context_token", "")):
        raise _deny()
    binding = _Binding(context, _immutable(context))
    return binding, _current.set(binding)


def close_graph_context(binding, token):
    # Child tasks inherit ContextVars. Closing the shared binding also prevents
    # a detached task from retaining authority after the verified dispatch exits.
    binding.active = False
    _current.reset(token)


def resolve_graph_context(saved_context: Any) -> Any:
    binding = _current.get()
    if binding is None:
        return saved_context
    if (not binding.active or _immutable(saved_context) != binding.immutable
            or _immutable(binding.context) != binding.immutable):
        raise _deny()
    return binding.context
