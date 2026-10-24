"""Private, per-handler authority for signed runtime-recovery checkpoints."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .capability_client import GatewayError
from .checkpoint_capacity import reply_limit

_STATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_HASH = re.compile(r"[a-f0-9]{64}")
_AGENT_GROUP_SCHEMA = "schema://agentplug/agent-group/v1"


def _platform_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return (encoded.replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def checkpoint_state_key(scope: Any, namespace: str, key: str) -> str:
    """Return the platform State key for an exact trusted scope/name tuple."""
    if (_STATE_NAME.fullmatch(namespace) is None or _STATE_NAME.fullmatch(key) is None):
        raise ValueError("bounded State namespace and key required")
    fields = ("tenant_id", "department_id", "application_id", "agent_id",
              "agent_instance_id", "principal_type", "principal_id", "installation_id",
              "agent_version_id", "session_id", "run_id")
    scope_values = [getattr(scope, name, None) for name in fields]
    if any(not isinstance(value, str) for value in scope_values):
        raise ValueError("complete trusted State scope required")
    prefix = hashlib.sha256(_platform_json(scope_values).encode("utf-8")).hexdigest()
    return hashlib.sha256(_platform_json([prefix, namespace, key]).encode("utf-8")).hexdigest()


CheckpointValueValidator = Callable[[Any, dict[str, Any], Mapping[tuple[str, str], dict[str, Any]]], bool]
CheckpointCompletion = Callable[[dict[str, Any]], bool]
InitialInputHashSelector = Callable[[Any, Mapping[tuple[str, str], dict[str, Any]]], str]
RecoveryCheckpointLoader = Callable[[Any, str, str, str], Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class RecoveryCheckpointStep:
    namespace: str
    key: str
    schema_id: str
    validate_checkpoint: CheckpointValueValidator
    is_complete: CheckpointCompletion
    allow_initial_start: bool = True
    initial_input_hash: str | InitialInputHashSelector | None = None


@dataclass(frozen=True)
class RecoveryCheckpointSnapshot:
    reference: dict[str, Any]
    response: dict[str, Any]


@dataclass(frozen=True)
class RecoveryPlan:
    steps: tuple[RecoveryCheckpointStep, ...]
    allow_group_resume: bool = False
    allowed_agent_group_key: str | None = None


RecoveryCheckpointSelector = Callable[
    [Any, tuple[RecoveryCheckpointSnapshot, ...], RecoveryCheckpointSnapshot | None], RecoveryPlan
]


@dataclass
class _RuntimeRecoveryState:
    request: Any
    plan: RecoveryPlan
    execution_revision: int
    load_checkpoint: RecoveryCheckpointLoader
    state_keys: dict[tuple[str, str], str]
    references: dict[tuple[str, str], dict[str, Any] | None]
    values: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    latest: dict[tuple[str, str], dict[str, Any] | None] = field(default_factory=dict)
    stage_index: int = 0
    initial_start_index: int | None = None
    absence_checked: set[tuple[str, str]] = field(default_factory=set)
    group_identity: tuple[str, str] | None = None
    initial_start_input_verified: set[tuple[str, str]] = field(default_factory=set)
    save_receipts: dict[tuple[tuple[str, str], int], str] = field(default_factory=dict)


_current_runtime_recovery: ContextVar[_RuntimeRecoveryState | None] = ContextVar(
    "agent_platform_runtime_recovery", default=None,
)


def set_runtime_recovery(state: _RuntimeRecoveryState):
    return _current_runtime_recovery.set(state)


def reset_runtime_recovery(token) -> None:
    _current_runtime_recovery.reset(token)


def current_runtime_recovery_active() -> bool:
    return _current_runtime_recovery.get() is not None


def _deny() -> GatewayError:
    return GatewayError("RECOVERY_STATE_UNAVAILABLE", "required recovery checkpoint is unavailable")


def _step_index(state: _RuntimeRecoveryState, namespace: str, key: str, schema_id: str) -> int | None:
    for index, step in enumerate(state.plan.steps):
        if (step.namespace, step.key) == (namespace, key):
            if step.schema_id != schema_id:
                raise _deny()
            return index
    return None


def _validate_checkpoint(state: _RuntimeRecoveryState, index: int,
                         checkpoint: Any) -> dict[str, Any]:
    step = state.plan.steps[index]
    if (not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("value"), dict)
            or checkpoint.get("schema_id") != step.schema_id):
        raise _deny()
    prior = {}
    for previous_index, previous_step in enumerate(state.plan.steps[:index]):
        identity = (previous_step.namespace, previous_step.key)
        if identity in state.values:
            prior[identity] = dict(state.values[identity])
    try:
        if step.validate_checkpoint(state.request, checkpoint, prior) is not True:
            raise _deny()
    except GatewayError:
        raise
    except Exception:
        raise _deny() from None
    return checkpoint["value"]


async def prepare_runtime_recovery_state(
    request: Any,
    plan: RecoveryPlan,
    snapshots: tuple[RecoveryCheckpointSnapshot, ...],
    execution_revision: int,
    load_checkpoint: RecoveryCheckpointLoader,
    *,
    group_identity: tuple[str, str] | None = None,
) -> _RuntimeRecoveryState:
    """Validate the selected exact workflow and confirm one safe next step."""
    if (not isinstance(plan, RecoveryPlan) or type(plan.allow_group_resume) is not bool
            or not isinstance(plan.steps, tuple) or not 1 <= len(plan.steps) <= 16
            or type(execution_revision) is not int or execution_revision < 1
            or not callable(load_checkpoint)):
        raise _deny()
    group_key = plan.allowed_agent_group_key
    if group_key is not None and (
            not isinstance(group_key, str) or _STATE_NAME.fullmatch(group_key) is None
            or not any(isinstance(step, RecoveryCheckpointStep)
                       and step.namespace == "coordination" and step.key == group_key
                       and step.schema_id == _AGENT_GROUP_SCHEMA for step in plan.steps)):
        raise _deny()
    if group_identity is not None and (
            not plan.allow_group_resume or group_key is None
            or group_identity != ("coordination", group_key)):
        raise _deny()
    snapshot_by_key: dict[str, RecoveryCheckpointSnapshot] = {}
    for snapshot in snapshots:
        if (not isinstance(snapshot, RecoveryCheckpointSnapshot)
                or not isinstance(snapshot.reference, dict)
                or not isinstance(snapshot.response, dict)):
            raise _deny()
        state_key = snapshot.reference.get("state_key")
        if not isinstance(state_key, str) or _HASH.fullmatch(state_key) is None or state_key in snapshot_by_key:
            raise _deny()
        snapshot_by_key[state_key] = snapshot

    state = _RuntimeRecoveryState(
        request=request, plan=plan, execution_revision=execution_revision,
        load_checkpoint=load_checkpoint, state_keys={}, references={},
        group_identity=group_identity,
    )
    seen_keys: set[str] = set()
    for index, step in enumerate(plan.steps):
        if (not isinstance(step, RecoveryCheckpointStep)
                or not isinstance(step.namespace, str) or _STATE_NAME.fullmatch(step.namespace) is None
                or not isinstance(step.key, str) or _STATE_NAME.fullmatch(step.key) is None
                or not isinstance(step.schema_id, str) or not step.schema_id.startswith("schema://")
                or len(step.schema_id.encode("utf-8")) > 256
                or any(char in step.schema_id for char in "\x00\r\n\t* ")
                or not callable(step.validate_checkpoint) or not callable(step.is_complete)
                or type(step.allow_initial_start) is not bool
                or (step.initial_input_hash is not None
                    and not callable(step.initial_input_hash)
                    and (not isinstance(step.initial_input_hash, str)
                         or _HASH.fullmatch(step.initial_input_hash) is None))):
            raise _deny()
        identity = (step.namespace, step.key)
        if identity in state.state_keys:
            raise _deny()
        try:
            state_key = checkpoint_state_key(request.scope, step.namespace, step.key)
        except (TypeError, ValueError):
            raise _deny() from None
        if state_key in seen_keys:
            raise _deny()
        seen_keys.add(state_key)
        state.state_keys[identity] = state_key
        snapshot = snapshot_by_key.get(state_key)
        reference = dict(snapshot.reference) if snapshot is not None else None
        state.references[identity] = reference
        state.latest[identity] = dict(reference) if reference is not None else None

    def later_has_reference(start: int) -> bool:
        return any(state.references[(step.namespace, step.key)] is not None
                   for step in plan.steps[start:])

    for index, step in enumerate(plan.steps):
        identity = (step.namespace, step.key)
        state_key = state.state_keys[identity]
        reference = state.references[identity]
        snapshot = snapshot_by_key.get(state_key)
        if snapshot is None:
            if (later_has_reference(index + 1) or not step.allow_initial_start
                    or step.initial_input_hash is None):
                raise _deny()
            try:
                current = await load_checkpoint(request, step.namespace, step.key, step.schema_id)
                normalized = _metadata(current, state_key, step.schema_id)
            except GatewayError:
                raise
            except Exception:
                raise _deny() from None
            if normalized["checkpoint"] is not None:
                raise _deny()
            state.stage_index = index
            state.initial_start_index = index
            state.absence_checked.add(identity)
            return state

        checkpoint = _metadata(snapshot.response, state_key, step.schema_id)["checkpoint"]
        if checkpoint is None or reference is None or not _matches_reference(snapshot.response, reference):
            raise _deny()
        value = _validate_checkpoint(state, index, checkpoint)
        state.values[identity] = dict(value)
        try:
            complete = step.is_complete(value)
        except Exception:
            raise _deny() from None
        if type(complete) is not bool:
            raise _deny()
        if not complete:
            if later_has_reference(index + 1):
                raise _deny()
            state.stage_index = index
            state.initial_start_index = None
            return state

    state.stage_index = len(plan.steps)
    state.initial_start_index = None
    return state


def _metadata(response: Any, state_key: str, schema_id: str) -> dict[str, Any]:
    if (not isinstance(response, dict) or set(response) - {"checkpoint_history"} != {"state_key", "checkpoint"}
            or response.get("state_key") != state_key):
        raise _deny()
    limit = reply_limit(response)
    checkpoint = response.get("checkpoint")
    if checkpoint is None:
        return {"state_key": state_key, "checkpoint": None}
    required = {"revision", "schema_id", "value", "content_hash", "execution_revision", "expires_at"}
    if (not isinstance(checkpoint, dict) or set(checkpoint) != required
            or type(checkpoint.get("revision")) is not int or not 1 <= checkpoint["revision"] <= limit
            or checkpoint.get("schema_id") != schema_id
            or not isinstance(checkpoint.get("value"), dict)
            or not isinstance(checkpoint.get("content_hash"), str)
            or _HASH.fullmatch(checkpoint["content_hash"]) is None
            or type(checkpoint.get("execution_revision")) is not int or checkpoint["execution_revision"] < 1
            or not isinstance(checkpoint.get("expires_at"), str)
            or not checkpoint["expires_at"] or len(checkpoint["expires_at"]) > 64):
        raise _deny()
    expiry = checkpoint["expires_at"]
    try:
        parsed_expiry = datetime.fromisoformat(
            expiry[:-1] + "+00:00" if expiry.endswith("Z") else expiry
        )
    except ValueError:
        raise _deny() from None
    if parsed_expiry.tzinfo is None or parsed_expiry.utcoffset() is None:
        raise _deny()
    return {"state_key": state_key, "checkpoint": checkpoint}


def _matches_reference(checkpoint: dict[str, Any], reference: dict[str, Any]) -> bool:
    current = checkpoint.get("checkpoint")
    return (current is not None and checkpoint.get("state_key") == reference.get("state_key")
            and all(current.get(field) == reference.get(field) for field in (
                "revision", "schema_id", "content_hash", "execution_revision", "expires_at")))


def observe_runtime_recovery_load(namespace: str, key: str,
                                  schema_id: str, response: dict[str, Any]) -> None:
    state = _current_runtime_recovery.get()
    if state is None:
        return
    identity = (namespace, key)
    index = _step_index(state, namespace, key, schema_id)
    if index is None:
        raise _deny()
    state_key = state.state_keys[identity]
    normalized = _metadata(response, state_key, schema_id)
    checkpoint = normalized["checkpoint"]
    reference = state.references[identity]
    latest = state.latest.get(identity, reference)
    if checkpoint is None:
        if (reference is not None or latest is not None or index != state.stage_index
                or state.initial_start_index != index):
            raise _deny()
        state.absence_checked.add(identity)
        return
    if reference is not None and latest is reference and not _matches_reference(normalized, reference):
        raise _deny()
    if latest is not None and not _matches_reference(normalized, latest):
        raise _deny()
    if index > state.stage_index:
        raise _deny()
    value = _validate_checkpoint(state, index, checkpoint)
    state.latest[identity] = {
        "state_key": state_key, "revision": checkpoint["revision"],
        "schema_id": schema_id, "content_hash": checkpoint["content_hash"],
        "execution_revision": checkpoint["execution_revision"],
        "expires_at": checkpoint["expires_at"],
    }
    state.values[identity] = dict(value)


def observe_runtime_recovery_save(namespace: str, key: str, schema_id: str,
                                  expected_revision: int, response: dict[str, Any]) -> None:
    state = _current_runtime_recovery.get()
    if state is None:
        return
    identity = (namespace, key)
    index = _step_index(state, namespace, key, schema_id)
    if index is None:
        raise _deny()
    if index != state.stage_index or type(expected_revision) is not int or expected_revision < 0:
        raise _deny()
    state_key = state.state_keys[identity]
    normalized = _metadata(response, state_key, schema_id)
    checkpoint = normalized["checkpoint"]
    if checkpoint is None:
        raise _deny()
    latest = state.latest.get(identity, state.references[identity])
    try:
        response_hash = hashlib.sha256(_platform_json(response).encode("utf-8")).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        raise _deny() from None
    previous_observation = state.save_receipts.get((identity, expected_revision))
    if (previous_observation == response_hash and latest is not None
            and _matches_reference(normalized, latest)):
        return
    prior_revision = 0 if latest is None else latest.get("revision")
    if (type(prior_revision) is not int or expected_revision != prior_revision
            or checkpoint["revision"] != expected_revision + 1
            or checkpoint["execution_revision"] != state.execution_revision):
        raise _deny()
    if state.references[identity] is None and identity not in state.initial_start_input_verified:
        raise _deny()
    value = _validate_checkpoint(state, index, checkpoint)
    state.latest[identity] = {
        "state_key": state_key, "revision": checkpoint["revision"],
        "schema_id": schema_id, "content_hash": checkpoint["content_hash"],
        "execution_revision": checkpoint["execution_revision"],
        "expires_at": checkpoint["expires_at"],
    }
    state.values[identity] = dict(value)
    state.save_receipts[(identity, expected_revision)] = response_hash


def validate_runtime_recovery_checkpoint(namespace: str, key: str, schema_id: str,
                                         response: dict[str, Any]) -> None:
    """Validate the actual response returned by the current public State read."""
    observe_runtime_recovery_load(namespace, key, schema_id, response)


def record_runtime_recovery_checkpoint_save(namespace: str, key: str, schema_id: str,
                                           expected_revision: int,
                                           response: dict[str, Any]) -> None:
    """Validate the actual checkpoint receipt returned by a public State save."""
    observe_runtime_recovery_save(namespace, key, schema_id, expected_revision, response)


def authorize_runtime_recovery_start(namespace: str, key: str, schema_id: str,
                                     input_hash: str) -> bool:
    """Authorize only the planned exact first write with its frozen input digest."""
    state = _current_runtime_recovery.get()
    if state is None:
        return False
    identity = (namespace, key)
    index = _step_index(state, namespace, key, schema_id)
    if (index is None or index != state.stage_index or state.initial_start_index != index
            or identity not in state.absence_checked
            or state.references[identity] is not None
            or not isinstance(input_hash, str) or _HASH.fullmatch(input_hash) is None):
        raise _deny()
    selector = state.plan.steps[index].initial_input_hash
    prior = {}
    for previous_step in state.plan.steps[:index]:
        prior_identity = (previous_step.namespace, previous_step.key)
        if prior_identity in state.values:
            prior[prior_identity] = dict(state.values[prior_identity])
    try:
        expected = selector(state.request, prior) if callable(selector) else selector
    except Exception:
        raise _deny() from None
    if not isinstance(expected, str) or _HASH.fullmatch(expected) is None or expected != input_hash:
        raise _deny()
    state.initial_start_input_verified.add(identity)
    return True


async def complete_runtime_recovery_step(namespace: str, key: str, schema_id: str) -> None:
    """Advance only from an SDK-observed complete public checkpoint."""
    state = _current_runtime_recovery.get()
    if state is None:
        return
    identity = (namespace, key)
    index = _step_index(state, namespace, key, schema_id)
    if index is None:
        raise _deny()
    if index < state.stage_index:
        value = state.values.get(identity)
        try:
            if value is None or state.plan.steps[index].is_complete(value) is not True:
                raise _deny()
        except GatewayError:
            raise
        except Exception:
            raise _deny() from None
        return
    if index != state.stage_index:
        raise _deny()
    value = state.values.get(identity)
    latest = state.latest.get(identity)
    try:
        if (value is None or latest is None
                or state.plan.steps[index].is_complete(value) is not True):
            raise _deny()
    except GatewayError:
        raise
    except Exception:
        raise _deny() from None
    state.stage_index += 1
    state.initial_start_index = None
    if state.stage_index >= len(state.plan.steps):
        return
    next_step = state.plan.steps[state.stage_index]
    next_identity = (next_step.namespace, next_step.key)
    if state.references[next_identity] is not None or not next_step.allow_initial_start:
        raise _deny()
    state.initial_start_index = state.stage_index
    try:
        current = await state.load_checkpoint(state.request, next_step.namespace,
                                              next_step.key, next_step.schema_id)
        normalized = _metadata(current, state.state_keys[next_identity], next_step.schema_id)
    except GatewayError:
        raise
    except Exception:
        raise _deny() from None
    if normalized["checkpoint"] is not None:
        raise _deny()
    state.absence_checked.add(next_identity)
