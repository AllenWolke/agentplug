"""Durable, ordered steps over public State and existing governed adapters.

The executor supplies execute/recover; recovery must reconcile existing model
and tool receipts, never redispatch an unknown operation. This module owns
plan identity, dependencies, reservations and deadlines, not domain rules.
"""
from __future__ import annotations

import copy
import asyncio
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Any, Protocol

from .capability_client import GatewayError
from .recovery_context import (
    authorize_runtime_recovery_start, complete_runtime_recovery_step,
    record_runtime_recovery_checkpoint_save, validate_runtime_recovery_checkpoint,
)

STATE_SCHEMA = "schema://agentplug/step-workflow/v1"
NAMESPACE = "step-workflow"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _stop(code: str) -> GatewayError:
    return GatewayError(code, "step workflow stopped at a governed boundary")


def _names(values: Any) -> bool:
    return (isinstance(values, list) and len(values) <= 32 and
            all(isinstance(value, str) and _NAME.fullmatch(value) for value in values) and
            len(set(values)) == len(values))


def _validate_steps(steps: Any, required_slots: list[str], maximum: int,
                    prior: list[dict] | None = None) -> list[dict]:
    if not isinstance(steps, list) or not steps or len(steps) > maximum:
        raise _stop("STEP_PLAN_REJECTED")
    frozen = json.loads(_json(steps))
    seen = {step["id"] for step in prior or []}
    for step in frozen:
        if (not isinstance(step, dict) or set(step) != {"id", "payload", "depends_on", "required_slots"}
                or not isinstance(step.get("id"), str) or not _NAME.fullmatch(step["id"])
                or step["id"] in seen or not isinstance(step["payload"], dict)
                or not _names(step["depends_on"]) or not set(step["depends_on"]) <= seen
                or not _names(step["required_slots"]) or not set(step["required_slots"]) <= set(required_slots)):
            raise _stop("STEP_PLAN_REJECTED")
        seen.add(step["id"])
    return frozen


class StepExecutor(Protocol):
    async def execute(self, step: dict, runtime: "StepRuntime", results: dict) -> dict: ...
    async def recover(self, step: dict, runtime: "StepRuntime", results: dict) -> dict: ...


@dataclass(frozen=True)
class StepRuntime:
    """Call reservations do not authorize dispatch; gateway policy still does.

    Call keys are stable across recovery. The adapter must use the SDK's
    receipt-aware model/tool operation for any potentially charged operation.
    """
    operation_key: str
    deadline_ms: int
    recovering: bool
    _remaining: Any
    _admit: Any
    _admit_many: Any = None

    def remaining(self) -> float:
        value = self._remaining()
        if value <= 0:
            raise _stop("STEP_DEADLINE_EXCEEDED")
        return value

    async def admit_call(self, kind: str, call_key: str) -> None:
        await self._admit(kind, call_key)

    async def admit_calls(self, calls: list[tuple[str, str]]) -> None:
        """Reserve an independent call set before its concurrent dispatch."""
        if self._admit_many is None:
            # Compatibility for adapters constructing an older local runtime.
            for kind, call_key in calls:
                await self._admit(kind, call_key)
        else:
            await self._admit_many(calls)


async def run_step_workflow(client, steps: list[dict], executor: StepExecutor, *, key: str,
                            required_slots: list[str], max_steps: int = 6,
                            max_calls: dict[str, int] | None = None, timeout: float = 60,
                            deadline_ms: int | None = None, additional_steps: list[dict] | None = None,
                            max_extensions: int = 1, cancelled=None, prepare_only: bool = False,
                            inspect_only: bool = False) -> dict:
    """Freeze an initial plan, execute serially, and permit bounded append-only repair.

    An incomplete plan enters awaiting_extension. Its original required slots
    cannot change. Additional steps append once; original steps/results remain
    immutable. Lost replies leave dispatch intent; only executor.recover runs.
    Cancellation and authority errors propagate with intent/reservations saved.
    inspect_only reads an existing, validated snapshot without creating state,
    changing its phase/budget, executing or recovering a pending operation.
    """
    if (not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key) is None
            or not _names(required_slots) or not required_slots
            or type(max_steps) is not int or not 1 <= max_steps <= 6
            or type(max_extensions) is not int or not 0 <= max_extensions <= 1
            or type(timeout) not in (float, int) or not math.isfinite(timeout) or not 0 < timeout <= 3600
            or (deadline_ms is not None and (type(deadline_ms) is not int or not 0 < deadline_ms <= (1 << 53) - 1))
            or type(prepare_only) is not bool or prepare_only and additional_steps is not None
            or type(inspect_only) is not bool or inspect_only and (prepare_only or additional_steps is not None)
            or (cancelled is not None and not callable(cancelled))
            or not callable(getattr(executor, "execute", None)) or not callable(getattr(executor, "recover", None))):
        raise _stop("STEP_CONFIG_INVALID")
    limits = copy.deepcopy(max_calls if max_calls is not None else {"operation": 16})
    if (not isinstance(limits, dict) or not 1 <= len(limits) <= 8
            or any(not isinstance(kind, str) or not _NAME.fullmatch(kind)
                   or type(value) is not int or not 1 <= value <= 32 for kind, value in limits.items())
            or sum(limits.values()) > 32):
        raise _stop("STEP_CONFIG_INVALID")
    initial = _validate_steps(steps, required_slots, max_steps)
    # The first admitted deadline is state, not a fresh caller clock reading.
    # Re-entering the workflow cannot extend it; an earlier new bound fails
    # closed in the state validation below.
    digest = hashlib.sha256(_json([initial, required_slots, max_steps, limits,
                                  max_extensions, timeout]).encode()).hexdigest()
    policy = await client.load_harness_policy(timeout=min(timeout, 10))
    entered = time.monotonic()
    deadline = policy["server_time_ms"] + min(timeout, policy["limits"]["max_elapsed_seconds"]) * 1000
    if deadline_ms is not None:
        deadline = min(deadline, deadline_ms)
    state = {"version": "step-workflow/v1", "input_hash": digest, "phase": "running",
             "steps": initial, "required_slots": list(required_slots), "results": {},
             "deadline_ms": int(deadline), "call_limits": limits, "reservations": {},
             "extensions": 0, "policy_hash": policy["policy_hash"], "pending": None}
    loaded = await client.load_checkpoint(NAMESPACE, key, STATE_SCHEMA, timeout=min(timeout, 10))
    validate_runtime_recovery_checkpoint(NAMESPACE, key, STATE_SCHEMA, loaded)
    checkpoint, revision = loaded.get("checkpoint"), 0
    if checkpoint is None:
        if inspect_only:
            raise _stop("STEP_RECONCILIATION_REQUIRED")
        authorize_runtime_recovery_start(NAMESPACE, key, STATE_SCHEMA, digest)
    else:
        revision, previous = checkpoint.get("revision"), checkpoint.get("value")
        if (type(revision) is not int or not 1 <= revision <= 63
                or not isinstance(previous, dict) or previous.get("version") != "step-workflow/v1"
                or previous.get("input_hash") != digest):
            raise _stop("STEP_STATE_REJECTED")
        state = copy.deepcopy(previous)
        _validate_steps(state.get("steps"), required_slots, max_steps)
        if (state["steps"][:len(initial)] != initial or state.get("required_slots") != required_slots
                or state.get("call_limits") != limits or state.get("phase") not in
                   {"running", "dispatch", "awaiting_extension", "completed", "cancelled", "incomplete"}
                or type(state.get("deadline_ms")) is not int or not 0 < state["deadline_ms"] <= deadline
                or type(state.get("extensions")) is not int or not 0 <= state["extensions"] <= max_extensions
                or not isinstance(state.get("results"), dict) or not isinstance(state.get("reservations"), dict)
                or len(state["reservations"]) > 32):
            raise _stop("STEP_STATE_REJECTED")
        ids = [step["id"] for step in state["steps"]]
        if (not set(state["results"]) <= set(ids) or any(
                ids[index] not in state["results"] for index in range(len(state["results"])))
                or (state["phase"] == "dispatch" and
                    (len(state["results"]) == len(ids) or state.get("pending") != ids[len(state["results"])]))
                or (state["phase"] != "dispatch" and state.get("pending") is not None)):
            raise _stop("STEP_STATE_REJECTED")
        for name, value in state["reservations"].items():
            if not isinstance(name, str) or not _NAME.fullmatch(name) or value not in limits:
                raise _stop("STEP_STATE_REJECTED")
        for step in state["steps"][:len(state["results"])]:
            _validate_result(state["results"][step["id"]], step)
        for kind, bound in limits.items():
            if list(state["reservations"].values()).count(kind) > bound:
                raise _stop("STEP_STATE_REJECTED")
        revalidate = getattr(executor, "revalidate", None)
        if revalidate is not None:
            if not callable(revalidate): raise _stop("STEP_CONFIG_INVALID")
            for step in state["steps"][:len(state["results"])]:
                # Reauthorization cannot mutate cached results or re-run a step.
                checked = await revalidate(copy.deepcopy(step), copy.deepcopy(state["results"][step["id"]]))
                if checked is not True: raise _stop("STEP_RESULT_AUTHORITY_DENIED")

    def remaining() -> float:
        return (state["deadline_ms"] - policy["server_time_ms"]) / 1000 - (time.monotonic() - entered)

    async def save() -> None:
        nonlocal revision
        if revision >= 63:
            raise _stop("STEP_STATE_LIMIT")
        receipt = await client.save_checkpoint(NAMESPACE, key, STATE_SCHEMA, copy.deepcopy(state), revision,
                                              f"steps-{revision + 1}", timeout=min(timeout, max(0.001, remaining())) if remaining() > 0 else 5)
        record_runtime_recovery_checkpoint_save(NAMESPACE, key, STATE_SCHEMA, revision, receipt)
        if receipt.get("checkpoint", {}).get("revision") != revision + 1:
            raise _stop("STEP_STATE_REJECTED")
        revision += 1

    reservation_lock = asyncio.Lock()

    async def admit_many(calls: list[tuple[str, str]]) -> None:
        # Parallel independent reads still share one parent State lineage.
        async with reservation_lock:
            await reserve_calls(calls)

    async def reserve_calls(calls: list[tuple[str, str]]) -> None:
        if not isinstance(calls, list) or not 1 <= len(calls) <= 32:
            raise _stop("STEP_CALL_REJECTED")
        reservations = dict(state["reservations"])
        for call in calls:
            if not isinstance(call, (tuple, list)) or len(call) != 2:
                raise _stop("STEP_CALL_REJECTED")
            kind, call_key = call
            if (not isinstance(kind, str) or kind not in limits
                    or not isinstance(call_key, str) or not _NAME.fullmatch(call_key)):
                raise _stop("STEP_CALL_REJECTED")
            if call_key in reservations:
                if reservations[call_key] != kind:
                    raise _stop("STEP_CALL_REJECTED")
                continue
            if len(reservations) >= 32 or list(reservations.values()).count(kind) >= limits[kind]:
                raise _stop("STEP_CALL_LIMIT_EXCEEDED")
            reservations[call_key] = kind
        if reservations == state["reservations"]:
            return
        if remaining() <= 0:
            raise _stop("STEP_DEADLINE_EXCEEDED")
        # Validate the whole set first. A rejected member cannot leave a
        # partial in-memory reservation; a lost CAS reply dispatches nothing.
        previous = state["reservations"]
        state["reservations"] = reservations
        try:
            await save()
        except BaseException:
            # Even if an adapter catches the error, an unacknowledged local
            # mutation must never look like durable permission to dispatch.
            # An identical retry uses the same CAS/idempotency identity.
            state["reservations"] = previous
            raise

    async def admit(kind: str, call_key: str) -> None:
        await admit_many([(kind, call_key)])

    def covered() -> set[str]:
        return {slot for result in state["results"].values() for slot in result["covered_slots"]}

    def output() -> dict:
        missing = [slot for slot in required_slots if slot not in covered()]
        return {"status": "completed" if state["phase"] == "completed" else
                           "cancelled" if state["phase"] == "cancelled" else "incomplete",
                "version": state["version"], "steps": copy.deepcopy(state["steps"]),
                "results": copy.deepcopy(state["results"]), "missing_slots": missing,
                "covered_slots": [slot for slot in required_slots if slot in covered()],
                "deadline_ms": state["deadline_ms"], "extensions": state["extensions"],
                "calls": {kind: list(state["reservations"].values()).count(kind) for kind in limits},
                "finish_reason": state.get("finish_reason", state["phase"])}

    if inspect_only:
        if state["policy_hash"] != policy["policy_hash"]:
            raise _stop("STEP_POLICY_REJECTED")
        return {**output(), "inspection": {"read_only": True, "phase": state["phase"],
            "pending_step": state.get("pending"), "reconciliation_required": state["phase"] == "dispatch",
            "expired": remaining() <= 0}}
    if revision == 0:
        await save()
    if prepare_only:
        # The same plan/state is used by later execution. Preparing performs no
        # adapter execution or call admission and cannot renew an old deadline.
        return {**output(), "admission": {"phase": state["phase"],
            "remaining_seconds": max(0.0, remaining())}}
    if additional_steps is not None:
        # An identical appended plan is a recovery of that extension, not a
        # second extension. Changed earlier steps are never accepted.
        appended = _validate_steps(additional_steps, required_slots, max_steps - len(initial), initial)
        if state["extensions"]:
            if state["steps"] != initial + appended:
                raise _stop("STEP_EXTENSION_REJECTED")
        else:
            if state["phase"] != "awaiting_extension" or state["extensions"] >= max_extensions:
                raise _stop("STEP_EXTENSION_REJECTED")
            state.update(steps=initial + appended, phase="running", extensions=1)
            await save()

    while True:
        if state["phase"] in {"completed", "cancelled", "incomplete", "awaiting_extension"}:
            if state["phase"] == "completed":
                if set(required_slots) != covered() or len(state["results"]) != len(state["steps"]):
                    raise _stop("STEP_STATE_REJECTED")
                await complete_runtime_recovery_step(NAMESPACE, key, STATE_SCHEMA)
            return output()
        recovering = state["phase"] == "dispatch"
        # Settle an already-dispatched outcome first; policy/deadline changes
        # never authorize repeating it, nor hide an unknown outcome as timeout.
        if not recovering:
            if state["policy_hash"] != policy["policy_hash"]:
                raise _stop("STEP_POLICY_REJECTED")
            if cancelled is not None and cancelled() is True:
                state.update(phase="cancelled", finish_reason="cancelled")
                await save()
                return output()
            if remaining() <= 0:
                state.update(phase="incomplete", finish_reason="elapsed_limit")
                await save()
                return output()
        if len(state["results"]) == len(state["steps"]):
            missing = set(required_slots) - covered()
            state.update(phase="completed" if not missing else
                         "awaiting_extension" if state["extensions"] < max_extensions else "incomplete",
                         finish_reason="completed" if not missing else "required_slots_missing")
            await save()
            continue
        step = state["steps"][len(state["results"])]
        if any(dependency not in state["results"] or state["results"][dependency]["status"] != "completed"
               for dependency in step["depends_on"]):
            state.update(phase="incomplete", pending=None, finish_reason="dependency_incomplete")
            await save()
            return output()
        operation_key = "step-" + hashlib.sha256(_json([key, digest, step]).encode()).hexdigest()
        if not recovering:
            await client.validate_current_execution()
            state.update(phase="dispatch", pending=step["id"])
            await save()
        runtime = StepRuntime(operation_key, state["deadline_ms"], recovering, remaining, admit, admit_many)
        method = executor.recover if recovering else executor.execute
        async with asyncio.timeout(min(timeout, 5) if recovering else runtime.remaining()):
            result = await method(copy.deepcopy(step), runtime, copy.deepcopy(state["results"]))
        if not isinstance(result, dict) or result.get("status") == "unknown":
            raise _stop("STEP_RECONCILIATION_REQUIRED")
        _validate_result(result, step)
        state["results"][step["id"]] = json.loads(_json(result))
        state.update(phase="running", pending=None)
        if (len(state["results"]) == len(state["steps"])
                and state["policy_hash"] == policy["policy_hash"]):
            # The final known result and its derived terminal status are one
            # atomic checkpoint. No external action lies between these two
            # values, so a second save only adds latency and another lost-ACK
            # boundary. Older running/all-results checkpoints still recover
            # through the existing completion branch above.
            missing = set(required_slots) - covered()
            state.update(phase="completed" if not missing else
                         "awaiting_extension" if state["extensions"] < max_extensions else "incomplete",
                         finish_reason="completed" if not missing else "required_slots_missing")
            if cancelled is not None and cancelled() is True:
                state.update(phase="cancelled", finish_reason="cancelled")
            elif remaining() <= 0:
                state.update(phase="incomplete", finish_reason="elapsed_limit")
        await save()


def _validate_result(result: Any, step: dict) -> None:
    if (not isinstance(result, dict) or result.get("status") not in {"completed", "incomplete"}
            or not _names(result.get("covered_slots"))
            or not set(result["covered_slots"]) <= set(step["required_slots"])
            or not isinstance(result.get("output"), dict)
            or (result["status"] != "completed" and result["covered_slots"])):
        raise _stop("STEP_RESULT_REJECTED")
