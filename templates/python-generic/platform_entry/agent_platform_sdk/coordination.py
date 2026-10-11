"""Run-scoped durable delegation, without polling or replaying uncertain admission."""

import hashlib
import json
import re

from .capability_client import GatewayError, _agent_operation_key
from .agent_group_resume import current_agent_group_resume
from .execution_lifecycle import AgentGroupPause
from .models import RecoveryCheckpointReference
from .recovery_context import authorize_runtime_recovery_start, complete_runtime_recovery_step

STATE_SCHEMA = "schema://agentplug/agent-group/v1"


def _stop(code="AGENT_GROUP_STATE_REJECTED"):
    return GatewayError(code, "delegation stopped at a governed boundary")


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def agent_group_plan_input_hash(operation_key, task_type, inputs):
    """Hash the exact canonical input accepted by the public AgentGroup runner."""
    if (not _agent_operation_key(operation_key) or not _agent_operation_key(task_type)
            or not isinstance(inputs, list) or not 1 <= len(inputs) <= 16):
        raise ValueError("invalid fixed AgentGroup plan")
    try:
        frozen = json.loads(_json(inputs))
        for item in frozen:
            if not isinstance(item, dict) or "policy_snapshot" in item or len(_json(item).encode()) > 65536:
                raise ValueError("invalid bounded child input")
        return hashlib.sha256(_json([operation_key, task_type, frozen]).encode()).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("invalid bounded AgentGroup plan") from exc


async def run_agent_group(client, inputs, *, key, operation_key, task_type, timeout=30):
    """Prepare/admit one frozen plan, then return one current group read.

    Resume uses the same run-scoped checkpoint. An uncertain admission first
    queries its original slot; only verified preparing may complete the same
    CAS admission. Unresolved reads stop. Outputs are
    not checkpointed: every disclosure rechecks current platform permission.
    """
    if (not isinstance(key, str) or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", key) is None
            or not _agent_operation_key(operation_key) or not _agent_operation_key(task_type)
            or not isinstance(inputs, list) or not 1 <= len(inputs) <= 16):
        raise _stop("REQUEST_INVALID")
    try:
        frozen = json.loads(_json(inputs))
        for item in frozen:
            if not isinstance(item, dict) or "policy_snapshot" in item or len(_json(item).encode()) > 65536:
                raise ValueError("invalid bounded input")
        digest = agent_group_plan_input_hash(operation_key, task_type, inputs)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise _stop("REQUEST_INVALID") from exc
    parent_id = getattr(client._context, "task_id", "")
    input_fingerprint = getattr(client._context, "input_fingerprint", "")
    resume_binding = client._current_group_resume_binding()
    if not parent_id or not _hash(input_fingerprint):
        raise _stop()
    if (resume_binding is not None
            and not resume_binding.begin_runner(parent_id, key, operation_key,
                input_fingerprint, digest, resume_binding.child_keys)):
        raise _stop("RUN_RESUME_UNCONFIRMED")
    state = {"version": "agent-group/v1", "group_key": key, "operation_key": operation_key,
             "parent_run_id": parent_id, "input_hash": digest,
             "input_fingerprint": input_fingerprint,
             "phase": "route", "ordinal": 0, "targets": [], "bindings": [], "child_keys": []}
    loaded = await client.load_checkpoint("coordination", key, STATE_SCHEMA, timeout=timeout)
    revision = 0
    checkpoint = loaded.get("checkpoint")
    if checkpoint is not None:
        if (not isinstance(checkpoint, dict) or type(checkpoint.get("revision")) is not int
                or not 1 <= checkpoint["revision"] <= 63):
            raise _stop()
        previous = checkpoint.get("value")
        state_fields = {"version", "group_key", "operation_key", "parent_run_id", "input_hash",
                        "input_fingerprint", "phase", "ordinal", "targets", "bindings", "child_keys"}
        if (not isinstance(previous, dict) or set(previous) != state_fields
                or previous.get("version") != state["version"]
                or previous.get("group_key") != key or previous.get("operation_key") != operation_key
                or previous.get("parent_run_id") != parent_id or previous.get("input_hash") != digest
                or previous.get("input_fingerprint") != input_fingerprint
                or not isinstance(previous.get("child_keys"), list)
                or not isinstance(previous.get("bindings"), list)
                or previous["child_keys"] != [item.get("child_key") for item in previous["bindings"]
                                               if isinstance(item, dict)]
                or len(previous["child_keys"]) != len(previous["bindings"])):
            raise _stop()
        revision, state = checkpoint["revision"], json.loads(_json(previous))
    phase, ordinal = state.get("phase"), state.get("ordinal")
    targets, bindings, child_keys = state.get("targets"), state.get("bindings"), state.get("child_keys")
    if (phase not in ("route", "prepare", "admitting", "gather") or type(ordinal) is not int
            or not 0 <= ordinal <= len(frozen) or not isinstance(targets, list)
            or not isinstance(bindings, list) or not isinstance(child_keys, list)
            or len(child_keys) != len(bindings)
            or (phase == "route" and (ordinal != 0 or targets or bindings))
            or (phase != "route" and len(targets) != len(frozen))
            or len(bindings) != ordinal + (1 if phase == "admitting" else 0)
            or len(bindings) > len(frozen)
            or (phase == "gather" and ordinal != len(frozen))
            or (phase in ("prepare", "admitting") and ordinal >= len(frozen))):
        raise _stop()
    seen_child_keys: set[str] = set()
    for index, binding in enumerate(bindings):
        if (not isinstance(targets[index], dict) or not isinstance(binding, dict)
                or not _hash(binding.get("child_key")) or not _hash(binding.get("input_fingerprint"))
                or binding.get("child_key") in seen_child_keys
                or binding.get("output_schema") != targets[index].get("output_schema")):
            raise _stop()
        seen_child_keys.add(binding["child_key"])
    if child_keys != [item["child_key"] for item in bindings]:
        raise _stop()

    if resume_binding is not None:
        if revision == 0 or phase != "gather" or checkpoint is None:
            raise _stop("RUN_RESUME_UNCONFIRMED")
        current_reference = {
            "state_key": loaded.get("state_key"),
            "revision": checkpoint.get("revision"),
            "schema_id": checkpoint.get("schema_id"),
            "content_hash": checkpoint.get("content_hash"),
            "execution_revision": checkpoint.get("execution_revision"),
            "expires_at": checkpoint.get("expires_at"),
        }
        child_keys = tuple(item["child_key"] for item in bindings)
        if current_reference != resume_binding.checkpoint or child_keys != resume_binding.child_keys:
            raise _stop("RUN_RESUME_UNCONFIRMED")

    async def save():
        nonlocal revision
        if revision >= 63:
            raise _stop("AGENT_GROUP_STATE_LIMIT")
        result = await client.save_checkpoint("coordination", key, STATE_SCHEMA,
                                              json.loads(_json(state)), revision,
                                              f"group-{revision + 1}", timeout=timeout)
        receipt = result.get("checkpoint")
        if (not isinstance(receipt, dict) or type(receipt.get("revision")) is not int
                or receipt["revision"] != revision + 1):
            raise _stop()
        revision += 1
        if state.get("phase") == "gather":
            await complete_runtime_recovery_step("coordination", key, STATE_SCHEMA)

    if revision == 0:
        authorize_runtime_recovery_start("coordination", key, STATE_SCHEMA, digest)
        await save()
    if state.get("phase") == "gather":
        await complete_runtime_recovery_step("coordination", key, STATE_SCHEMA)
    for _ in range(36):
        phase, ordinal = state["phase"], state["ordinal"]
        if phase == "route":
            result = await client.route_agents(operation_key, task_type, len(frozen), timeout=timeout)
            state["targets"] = [{"input_schema": target["input_schema"], "output_schema": target["output_schema"]}
                                for target in result["route"]["targets"]]
            state["phase"] = "prepare"
            await save()
        elif phase == "prepare":
            result = await client.prepare_agent_child(operation_key, ordinal,
                                                       state["targets"][ordinal]["input_schema"],
                                                       frozen[ordinal], timeout=timeout)
            prepared = result["preparation"]
            binding = {"child_key": prepared["child_key"], "input_fingerprint": prepared["input_fingerprint"],
                       "output_schema": state["targets"][ordinal]["output_schema"]}
            state["bindings"].append(binding)
            state["child_keys"].append(binding["child_key"])
            state["phase"] = "admitting"
            # Boundary must be durable before any admission request.
            await save()
            await client.admit_agent_child(operation_key, ordinal, binding["child_key"],
                                           binding["input_fingerprint"], timeout=timeout)
            state["ordinal"] += 1
            state["phase"] = "gather" if state["ordinal"] == len(frozen) else "prepare"
            await save()
        elif phase == "admitting":
            binding = state["bindings"][ordinal]
            result = await client.read_agent_admission_state(operation_key, ordinal, binding["child_key"],
                                                              binding["input_fingerprint"], binding["output_schema"], timeout=timeout)
            if result["admission_state"]["status"] == "preparing":
                await client.admit_agent_child(operation_key, ordinal, binding["child_key"],
                                               binding["input_fingerprint"], timeout=timeout)
            state["ordinal"] += 1
            state["phase"] = "gather" if state["ordinal"] == len(frozen) else "prepare"
            await save()
        elif phase == "gather":
            if resume_binding is not None and not resume_binding.permit_gather():
                raise _stop("RUN_RESUME_UNCONFIRMED")
            result = await client.gather_agent_children(operation_key,
                [{"child_key": item["child_key"], "output_schema": item["output_schema"]}
                 for item in state["bindings"]], timeout=timeout)
            group = result.get("group") if isinstance(result, dict) else None
            if not isinstance(group, dict):
                raise _stop("AGENT_GROUP_REJECTED")
            terminal_success = (group.get("terminal") is True
                                and group.get("status") == "completed"
                                and group.get("outputs_complete") is True)
            if resume_binding is not None:
                if not resume_binding.finish_gather(terminal_success):
                    raise _stop("RUN_RESUME_UNCONFIRMED")
                if terminal_success and current_agent_group_resume.get() is resume_binding:
                    # The current permission-checked gather is now consumed.
                    # Subsequent business recovery uses normal live capability
                    # authorization; the outer lifecycle still owns the binding.
                    current_agent_group_resume.set(None)
            if terminal_success:
                return result
            if group.get("terminal") is True:
                raise _stop("AGENT_GROUP_REJECTED")
            if (group.get("terminal") is not False or state.get("ordinal") != len(frozen)
                    or len(state.get("bindings", [])) != len(frozen)):
                raise _stop("AGENT_GROUP_REJECTED")
            # A pause is valid only when the durable coordination head still
            # contains this exact, fully admitted gather plan.
            loaded = await client.load_checkpoint("coordination", key, STATE_SCHEMA, timeout=timeout)
            try:
                if (not isinstance(loaded, dict) or set(loaded) != {"state_key", "checkpoint"}
                        or not isinstance(loaded.get("checkpoint"), dict)):
                    raise ValueError
                current = loaded["checkpoint"]
                if (set(current) != {"revision", "schema_id", "value", "content_hash",
                                     "execution_revision", "expires_at"}
                        or type(current.get("revision")) is not int or current["revision"] != revision
                        or current.get("schema_id") != STATE_SCHEMA
                        or current.get("value") != state
                        or not _hash(current.get("content_hash"))
                        or type(current.get("execution_revision")) is not int
                        or current["execution_revision"] < 1):
                    raise ValueError
                reference = RecoveryCheckpointReference.model_validate({
                    "state_key": loaded["state_key"],
                    "revision": current["revision"],
                    "schema_id": current["schema_id"],
                    "content_hash": current["content_hash"],
                    "execution_revision": current["execution_revision"],
                    "expires_at": current["expires_at"],
                })
                child_keys = [item["child_key"] for item in state["bindings"]]
                if not 1 <= len(child_keys) <= 16 or len(set(child_keys)) != len(child_keys):
                    raise ValueError
            except (TypeError, ValueError, KeyError):
                raise _stop("AGENT_GROUP_REJECTED") from None
            raise AgentGroupPause(key, operation_key, reference, child_keys)
        else:
            raise _stop()
    raise _stop("AGENT_GROUP_STATE_LIMIT")
