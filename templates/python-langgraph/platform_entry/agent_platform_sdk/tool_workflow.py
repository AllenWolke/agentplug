"""Operation-bound approvals for durable graphs, without replaying uncertain writes.

The graph owns business checkpoints. This adapter owns only an SDK pause
projection and real Registry exit evidence; platform State/IAM/ledger and the
public approval transaction remain authoritative. Tokens exist only in the
current verified dispatch context, never in graph State or reports.
"""
from __future__ import annotations

import copy
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from .capability_client import GatewayError
from .errors import DomainExecutionError
from .execution_lifecycle import ExecutionLifecycle, HarnessPause
from .harness import STATE_SCHEMA
from .lifecycle import MemoryRunStore, generation_sequence_range
from .models import ExecuteRequest, ExecuteResponse, HandlerHandoff
from .task_registry import ExecutionTaskRegistry
from .graph_context import bind_graph_context, close_graph_context


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _deny():
    return DomainExecutionError("RUN_RESUME_UNCONFIRMED")


@dataclass
class _Dispatch:
    request: ExecuteRequest
    token: str = ""
    approved_key: str = ""
    approved_call: str = ""
    approved_name: str = ""
    pause: HarnessPause | None = None


_dispatch: ContextVar[_Dispatch | None] = ContextVar("governed_graph_tool_dispatch", default=None)


async def run_tool_operation(client, name: str, payload: dict, *, key: str,
                             timeout: float = 30, execute_approved: bool = True,
                             recovery_only: bool = False) -> dict:
    """Run one deterministic tool operation or return a safe approval pause.

    A dispatch intent is committed before invocation. After a lost reply only
    the receipt endpoint is read; even NOT_FOUND never authorizes replay.
    Callers must persist computed business results before entering this node.
    """
    if (not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", name) is None
            or not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key) is None
            or not isinstance(payload, dict) or type(recovery_only) is not bool):
        raise DomainExecutionError("INVALID_REQUEST")
    run_id = getattr(client._context, "task_id", "")
    # task_id is the trusted platform RunID, not a reusable business task ID.
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128 or run_id.strip() != run_id:
        raise DomainExecutionError("INVALID_REQUEST")
    canonical = _json([run_id, name, payload, key])
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    # A changed request must conflict with the same intent, never acquire a new
    # external identity. The independent input_hash above still binds all args.
    intent = _json(["tool-intent/v1", run_id, key])
    call_id = "wf-" + hashlib.sha256(intent.encode()).hexdigest()
    operation = {"name": name, "call_id": call_id, "payload": copy.deepcopy(payload),
                 "model_call_id": call_id, "run_id": run_id}
    loaded = await client.load_checkpoint("harness", key, STATE_SCHEMA, timeout=timeout)
    checkpoint = loaded.get("checkpoint")
    revision = 0
    state = {"version": "harness-loop/v1", "driver": "tool-operation/v1",
             "input_hash": digest, "phase": "tool", "pending": [operation]}
    if checkpoint is not None:
        revision = checkpoint.get("revision")
        state = copy.deepcopy(checkpoint.get("value"))
        if (type(revision) is not int or not 1 <= revision <= 62
                or not isinstance(state, dict) or state.get("version") != "harness-loop/v1"
                or state.get("driver") != "tool-operation/v1" or state.get("input_hash") != digest
                or state.get("phase") not in {"tool", "tool_dispatch", "approval_required", "done"}
                or state.get("pending") != ([] if state.get("phase") == "done" else [operation])):
            raise _deny()
    if recovery_only and state["phase"] not in {"done", "tool_dispatch"}:
        # Receipt recovery after a parent deadline cannot dispatch an operation
        # that has no saved send boundary, including an approved-but-unsent one.
        raise GatewayError("TOOL_OPERATION_NOT_DISPATCHED", "read-only receipt recovery requires saved dispatch")
    async def save():
        nonlocal revision
        receipt = await client.save_checkpoint("harness", key, STATE_SCHEMA, copy.deepcopy(state),
            revision, f"operation-{revision + 1}", timeout=timeout)
        if receipt.get("checkpoint", {}).get("revision") != revision + 1:
            raise _deny()
        revision += 1
    if state["phase"] == "done":
        result = copy.deepcopy(state["receipt"])
        if state.get("requires_confirmation"):
            result["workflow_approval"] = {"harness_key": key, "tool_name": name, "call_id": call_id}
        return result
    dispatch = _dispatch.get()
    confirmation = ""
    if state["phase"] == "approval_required":
        if (execute_approved and dispatch is not None and dispatch.token and dispatch.approved_key == key
                and dispatch.approved_call == call_id and dispatch.approved_name == name
                and dispatch.request.scope.run_id == run_id):
            confirmation, dispatch.token = dispatch.token, ""
        else:
            if dispatch is None or dispatch.request.scope.run_id != run_id:
                raise _deny()
            dispatch.pause = HarnessPause(key, name, call_id)
            return {"status": "approval_required", "harness_key": key,
                    "tool_name": name, "call_id": call_id}
    recovering = state["phase"] == "tool_dispatch"
    if not recovering:
        state["phase"] = "tool_dispatch"
        await save()
    try:
        if recovering:
            result = await client._post("/internal/tool/receipt", {"name": name, "call_id": call_id,
                                       "payload": payload}, timeout)
            if (result.get("version") != "tool-receipt/v1" or result.get("tool_name") != name
                    or result.get("call_id") != call_id or result.get("status") != "completed"
                    or not isinstance(result.get("receipt"), dict)):
                raise GatewayError("TOOL_RESULT_UNKNOWN", "explicit reconciliation required")
            result = result["receipt"]
        else:
            result = await client.invoke_tool(name, payload, call_id=call_id,
                                             confirmation_token=confirmation, timeout=timeout)
    except GatewayError as error:
        if recovering or error.code != "TOOL_CONFIRMATION_REQUIRED":
            raise
        state["phase"] = "approval_required"
        state["requires_confirmation"] = True
        await save()
        if dispatch is None or dispatch.request.scope.run_id != run_id:
            raise _deny()
        dispatch.pause = HarnessPause(key, name, call_id)
        return {"status": "approval_required", "harness_key": key,
                "tool_name": name, "call_id": call_id}
    observation = result.get("observation")
    if (not isinstance(observation, dict) or observation.get("version") != "runtime-observation/v1"
            or observation.get("tool_name") != name or observation.get("call_id") != call_id
            or observation.get("status") != "succeeded" or observation.get("effect") != "completed"
            or observation.get("instruction_trust") != "untrusted_data"):
        raise GatewayError("TOOL_RESULT_UNKNOWN", "successful governed Observation required")
    state.update(phase="done", pending=[], receipt=copy.deepcopy(result))
    await save()
    if dispatch is not None and dispatch.pause is not None and dispatch.pause.metadata["call_id"] == call_id:
        dispatch.pause = None
    if state.get("requires_confirmation"):
        result["workflow_approval"] = {"harness_key": key, "tool_name": name, "call_id": call_id}
    return result


async def run_graph_tool(client, name: str, payload: dict, *, key: str, timeout: float = 30) -> dict:
    """Consume durable LangGraph interrupts in the same order after restart.

    A completed approved operation still consumes its old interrupt slot before
    returning its receipt. Thus the next write cannot consume a former approval.
    """
    from langgraph.types import interrupt
    result = await run_tool_operation(client, name, payload, key=key, timeout=timeout,
                                      execute_approved=False)
    if result.get("status") == "approval_required" or result.get("workflow_approval"):
        reference = result.get("workflow_approval") or {
            field: result[field] for field in ("harness_key", "tool_name", "call_id")}
        interrupt({"kind": "tool_confirmation", **reference})
        if result.get("status") == "approval_required":
            result = await run_tool_operation(client, name, payload, key=key, timeout=timeout)
            if result.get("status") == "approval_required":
                raise _deny()
    result.pop("workflow_approval", None)
    return result


class GraphToolApproval:
    """Transport bridge for a scoped durable graph using run_tool_operation.

    Instantiate with the SAME Registry as create_fastapi_agent_app. The
    transport calls finalize only after execute() has actually exited. An
    ordinary business review does not manufacture a tool handoff.
    """
    def __init__(self, registry: ExecutionTaskRegistry):
        self.registry = registry
        self._waiting: dict[str, tuple] = {}

    async def execute(self, request: ExecuteRequest, client, work) -> ExecuteResponse:
        binding = _Dispatch(request)
        resume = request.resume_input or {}
        runtime_refs = None
        runtime = resume.get("version") in {"runtime-recovery/v1", "runtime-recovery/v2"}
        approval = resume
        if runtime and "confirmation_token" in resume:
            from .checkpoint_reference_set import runtime_parts
            identity = ExecutionLifecycle._identity(request)
            generation = json.loads(identity.key)
            _, runtime_refs, group = await runtime_parts(request, client, identity, generation[1])
            marker = resume.get("tool_resume")
            if group is not None or not isinstance(marker, dict):
                raise _deny()
            approval = {"confirmation_token": resume["confirmation_token"],
                        "handoff": marker["handoff"], "checkpoint": marker["checkpoint"]}
        if "confirmation_token" in resume:
            if (request.operation != "resume" or set(approval) != {"confirmation_token", "handoff", "checkpoint"}
                    or self.registry.has_other_active_generation(request)):
                raise _deny()
            token = resume["confirmation_token"]
            if not isinstance(token, str) or not token or len(token.encode()) > 8192:
                raise _deny()
            try:
                handoff = HandlerHandoff.model_validate(approval["handoff"])
                reference = approval["checkpoint"]
                identity = ExecutionLifecycle._identity(request)
                generation = json.loads(identity.key)
                sequence_base, _ = generation_sequence_range(generation[1])
                if (handoff.run_id != request.scope.run_id or handoff.input_fingerprint != identity.business_hash
                        or handoff.execution_revision >= generation[1] or handoff.lease_token_hash == generation[2]
                        or handoff.origin_operation not in {"invoke", "run"} or sequence_base < handoff.last_event_seq
                        or not isinstance(reference, dict)
                        or set(reference) != {"namespace", "key", "schema_id", "revision", "content_hash", "execution_revision"}
                        or reference["namespace"] != "harness" or reference["key"] != handoff.harness_key
                        or type(reference["revision"]) is not int or not 1 <= reference["revision"] <= 62
                        or type(reference["execution_revision"]) is not int
                        or not isinstance(reference["content_hash"], str)
                        or re.fullmatch(r"[a-f0-9]{64}", reference["content_hash"]) is None
                        or reference["schema_id"] != STATE_SCHEMA or reference["execution_revision"] != handoff.execution_revision):
                    raise _deny()
                if runtime_refs is not None:
                    from .recovery_context import checkpoint_state_key
                    expected = checkpoint_state_key(request.scope, "harness", handoff.harness_key)
                    matches = [cp for cp in runtime_refs if cp["state_key"] == expected]
                    if len(matches) != 1 or any(matches[0][field] != reference[field] for field in
                            ("revision", "schema_id", "content_hash", "execution_revision")):
                        raise _deny()
                loaded = await client.load_checkpoint("harness", handoff.harness_key, STATE_SCHEMA)
                cp = loaded.get("checkpoint")
                value = cp.get("value") if isinstance(cp, dict) else None
                pending = value.get("pending") if isinstance(value, dict) else None
                if (not isinstance(cp, dict) or any(cp.get(k) != reference[k] for k in
                        ("revision", "schema_id", "content_hash", "execution_revision"))
                        or not isinstance(value, dict) or value.get("version") != "harness-loop/v1" or value.get("driver") != "tool-operation/v1"
                        or value.get("phase") != "approval_required" or not isinstance(pending, list) or len(pending) != 1
                        or pending[0].get("name") != handoff.tool_name or pending[0].get("call_id") != handoff.call_id):
                    raise _deny()
            except (KeyError, TypeError, ValueError):
                raise _deny() from None
            binding.token, binding.approved_key = token, handoff.harness_key
            binding.approved_call, binding.approved_name = handoff.call_id, handoff.tool_name
        await client.validate_current_execution()
        graph_binding, graph_token = bind_graph_context(request, client._context)
        context_token = _dispatch.set(binding)
        try:
            response = await work()
            if binding.pause is not None:
                if response.status != "waiting" or response.run_id != request.scope.run_id:
                    raise _deny()
                identity = ExecutionLifecycle._identity(request)
                generation = json.loads(identity.key)
                if len(self._waiting) >= 4096 and identity.key not in self._waiting:
                    raise DomainExecutionError("EXECUTION_CAPACITY_EXCEEDED")
                # Actual graph interruption happened. Reuse SDK projection and
                # event sequencing; this record alone is never exit evidence.
                projection = MemoryRunStore()
                projection.start_generation(request.scope, request.idempotency_key, generation[1])
                projection.mark_waiting(request.scope.run_id, binding.pause.metadata)
                record = projection.get_run(request.scope.run_id)
                origin = resume.get("handoff", {}).get("origin_operation", request.operation)
                if origin not in {"run", "invoke"}:
                    origin = "invoke"  # new graph operations are dispatched through invoke
                self._waiting[identity.key] = (identity, binding.pause.metadata, record.events[-1].seq, origin)
                response = response.model_copy(update={"output": {**response.output,
                    "tool_confirmation": dict(binding.pause.metadata)}})
            return response
        finally:
            # Token is cleared even on exception/cancel; it is never persisted.
            binding.token = ""
            _dispatch.reset(context_token)
            close_graph_context(graph_binding, graph_token)

    def finalize_response(self, request: ExecuteRequest, response: ExecuteResponse) -> ExecuteResponse:
        response = response.model_copy(update={"handoff": None, "agent_group_handoff": None})
        identity = ExecutionLifecycle._identity(request)
        pending = self._waiting.get(identity.key)
        if pending is None:
            return response
        if (pending[0] != identity or response.status != "waiting"
                or response.run_id != request.scope.run_id or not self.registry.has_exit_proof(request)
                or response.output.get("tool_confirmation") != pending[1]):
            raise DomainExecutionError("RUN_HANDOFF_UNCONFIRMED")
        generation = json.loads(identity.key)
        receipt = HandlerHandoff(version="sdk-handler-exit/v1", run_id=request.scope.run_id,
            execution_revision=generation[1], body_hash=identity.body_hash,
            lease_token_hash=generation[2], input_fingerprint=identity.business_hash,
            origin_operation=pending[3], harness_key=pending[1]["harness_key"],
            tool_name=pending[1]["tool_name"], call_id=pending[1]["call_id"], last_event_seq=pending[2])
        return response.model_copy(update={"handoff": receipt})


def graph_tool_resume_input(request: ExecuteRequest) -> dict | None:
    """Redact the bearer token before any LangGraph resume value is persisted."""
    binding = _dispatch.get()
    if binding is None or binding.request is not request or not binding.approved_key:
        return None
    return {"kind": "tool_confirmation", "harness_key": binding.approved_key,
            "tool_name": binding.approved_name, "call_id": binding.approved_call}


async def recover_graph_tool_interrupt(request, client, interrupts):
    """Resume only the exact approval slot or a receipt reconciliation slot."""
    values = [getattr(item, "value", None) for item in interrupts]
    candidates = [value for value in values if isinstance(value, dict) and value.get("kind") == "tool_confirmation"]
    if not candidates:
        if "confirmation_token" in (request.resume_input or {}): raise _deny()
        return None
    if len(values) != 1 or len(candidates) != 1:
        raise _deny()
    value = candidates[0]
    if set(value) != {"kind", "harness_key", "tool_name", "call_id"}:
        raise _deny()
    approved = graph_tool_resume_input(request)
    if approved is not None:
        if approved != value: raise _deny()
        return approved
    if "confirmation_token" in (request.resume_input or {}): raise _deny()
    loaded = await client.load_checkpoint("harness", value["harness_key"], STATE_SCHEMA)
    cp = loaded.get("checkpoint")
    state = cp.get("value") if isinstance(cp, dict) else None
    if (not isinstance(state, dict) or state.get("version") != "harness-loop/v1"
            or state.get("driver") != "tool-operation/v1"):
        raise _deny()
    if state.get("phase") == "done":
        observation = state.get("receipt", {}).get("observation", {})
        if (state.get("pending") != [] or observation.get("tool_name") != value["tool_name"]
                or observation.get("call_id") != value["call_id"] or observation.get("effect") != "completed"):
            raise _deny()
        return value
    if state.get("phase") == "tool_dispatch":
        pending = state.get("pending")
        if (isinstance(pending, list) and len(pending) == 1
                and pending[0].get("name") == value["tool_name"] and pending[0].get("call_id") == value["call_id"]):
            return value  # run_tool_operation reads the receipt; it cannot resend.
    raise _deny()

