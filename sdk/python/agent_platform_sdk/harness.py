"""Persistent governed loop; uncertain dispatch never triggers automatic replay."""
import asyncio
import copy
import hashlib
import json
import math
import re
import time

from .capability_client import GatewayError
from .recovery_context import (authorize_runtime_recovery_start, complete_runtime_recovery_step,
    record_runtime_recovery_checkpoint_save, validate_runtime_recovery_checkpoint)

STATE_SCHEMA = "schema://agentplug/harness-loop/v1"
EXTENDED_STATE_SCHEMA = "schema://agentplug/harness-loop/v2"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _stop(code):
    return GatewayError(code, "harness stopped at a governed boundary")


async def _load_entry(client, key, schema, timeout):
    """Overlap two independent, currently authorized reads, never a send.

    No permission, policy or checkpoint is cached. Both reads must succeed
    before state validation or any mutation; CAS still owns write races. An
    error/cancellation drains both tasks and keeps the original exception.
    """
    policy_task = asyncio.create_task(client.load_harness_policy(timeout=min(float(timeout), 10.0)))
    checkpoint_task = asyncio.create_task(client.load_checkpoint("harness", key, schema,
        timeout=float(timeout)))
    try:
        policy = await policy_task
        entry_started = time.monotonic()
        try:
            loaded = await asyncio.wait_for(checkpoint_task,
                timeout=min(float(timeout), policy["limits"]["max_elapsed_seconds"]))
        except TimeoutError as error:
            raise _stop("UPSTREAM_TIMEOUT") from error
        return policy, loaded, entry_started
    finally:
        for task in (policy_task, checkpoint_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(policy_task, checkpoint_task, return_exceptions=True)


def _budget_exhausted(result):
    if "run_budget" not in result:
        return False
    budget = result["run_budget"]
    if (not isinstance(budget, dict) or budget.get("version") != "run-tree-budget/v1"
            or type(budget.get("exhausted")) is not bool or type(budget.get("exceeded")) is not bool
            or not isinstance(budget.get("root_run_id"), str) or not budget["root_run_id"]):
        raise _stop("HARNESS_BUDGET_REJECTED")
    return budget["exhausted"] or budget["exceeded"]


def _budget_output(previous, reason="budget_exhausted"):
    output = {"completion_status": "incomplete", "finish_reason": reason}
    output.update({key: copy.deepcopy(value) for key, value in (previous or {}).items()
                   if key in ("text", "model", "usage", "billing", "run_budget", "prompt_template_hash",
                              "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id")})
    if reason == "budget_exhausted":
        output["termination_reason"] = "MODEL_BUDGET_EXCEEDED"
    return output


def _limit_output(previous, finish_reason):
    output = {"completion_status": "incomplete", "termination_reason": "HARNESS_LIMIT_EXCEEDED",
              "finish_reason": finish_reason}
    output.update({key: copy.deepcopy(value) for key, value in (previous or {}).items()
                   if key in ("text", "model", "usage", "billing", "run_budget", "prompt_template_hash",
                              "routing", "route_execution", "context_cache", "response_schema", "model_version_id", "provider_id", "model_id", "step_id")})
    return output


def _tool_semantic_digest(name, payload):
    # Match Go's sorted JSON object and HTML-safe string encoding for this new
    # digest only. Keep the payload's parsed numeric forms intact; the shared
    # cross-language fixture owns edge-case number normalization.
    encoded = json.dumps([name, payload], ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"), allow_nan=False)
    encoded = (encoded.replace("&", r"\u0026").replace("<", r"\u003c")
               .replace(">", r"\u003e").replace("\u2028", r"\u2028")
               .replace("\u2029", r"\u2029"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


_POLICY_STATE_FIELDS = ("loop_policy_hash", "loop_limits", "loop_deadline_ms",
                        "tool_repeats", "repeat_counted_call_id")


class _HarnessLimitHandled(Exception):
    """An incomplete limit outcome was saved and the loop should re-read State."""


def _tool_context(receipt, operation):
    # New persisted Harness state requires versioned Observation, not legacy raw output.
    observation = receipt.get("observation")
    if (not isinstance(observation, dict) or observation.get("version") != "runtime-observation/v1"
            or observation.get("tool_name") != operation["name"]
            or observation.get("call_id") != operation["call_id"]
            or observation.get("status") not in ("succeeded", "failed", "timeout", "cancelled") or observation.get("effect") != "completed"
            or observation.get("instruction_trust") != "untrusted_data" or "context_output" not in observation):
        raise _stop("TOOL_OBSERVATION_REJECTED")
    if len(_json(observation["context_output"]).encode()) > 2048:
        raise _stop("TOOL_OBSERVATION_REJECTED")
    return {"version": observation["version"], "tool_name": operation["name"], "status": observation["status"],
            "error_type": observation.get("error_type", ""),
            "effect": "completed", "instruction_trust": "untrusted_data",
            "context_output": observation["context_output"],
            "context_truncated": observation.get("context_truncated", False),
            "output_truncated": observation.get("truncated", False)}


_SKILL_EDGE_WHITESPACE = " \t\n\r\v\f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def _skill_identifier(value):
    if not isinstance(value, str) or not value or value.strip(_SKILL_EDGE_WHITESPACE) != value or any(c in value for c in ("*", "\0", "\r", "\n")):
        return False
    try:
        return len(value.encode("utf-8")) <= 128
    except UnicodeEncodeError:
        return False


async def run_harness(client, input, *, key, max_rounds=4, max_tool_calls=8,
                      confirmation_token="", timeout=30, action_validator=None,
                      progress_evaluator=None, extension_id="", deadline_ms=None):
    """Run published functions with optional, deterministic business guards.

    Guards receive copies and must not perform I/O. ``action_validator`` returns
    exactly True to admit an operation. ``progress_evaluator`` returns None to
    continue or an outcome with completion_status completed/incomplete to stop.
    An extension identifier pins their business semantics to the checkpoint.
    Extensions use v2; calls without extensions retain the original v1 format.
    """
    extended = any(value is not None for value in (action_validator, progress_evaluator, deadline_ms)) or bool(extension_id)
    if (not isinstance(key, str) or not key or type(max_rounds) is not int or not 1 <= max_rounds <= 8
            or type(max_tool_calls) is not int or not 1 <= max_tool_calls <= 16
            or not isinstance(confirmation_token, str) or len(confirmation_token.encode()) > 8192
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0):
        raise _stop("HARNESS_CONFIG_INVALID")
    if (any(value is not None and not callable(value) for value in (action_validator, progress_evaluator))
            or (extended and (not isinstance(extension_id, str)
                             or re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", extension_id) is None))
            or (deadline_ms is not None and (type(deadline_ms) is not int or not 0 < deadline_ms <= (1 << 53) - 1))):
        raise _stop("HARNESS_CONFIG_INVALID")
    schema = EXTENDED_STATE_SCHEMA if extended else STATE_SCHEMA
    current = json.loads(_json(input))
    current.pop("deadline_ms", None)  # Only the saved, negotiated loop deadline is sent.
    skill_requests = current.pop("skill_requests", [])
    current.pop("skill_bindings", None)
    if not isinstance(skill_requests, list) or len(skill_requests) > 4:
        raise _stop("HARNESS_SKILL_REJECTED")
    seen = set()
    for request in skill_requests:
        if (not isinstance(request, dict) or set(request) - {"skill_id", "sections"}
                or not _skill_identifier(request.get("skill_id")) or request["skill_id"] in seen):
            raise _stop("HARNESS_SKILL_REJECTED")
        seen.add(request["skill_id"])
        sections = request.get("sections", [])
        if (not isinstance(sections, list) or len(sections) > 4
                or any(not _skill_identifier(section) for section in sections)
                or len(set(sections)) != len(sections)):
            raise _stop("HARNESS_SKILL_REJECTED")
    messages, operation_key = current.get("messages"), current.get("idempotency_key")
    if not isinstance(messages, list) or not messages or not isinstance(operation_key, str) or not operation_key:
        raise _stop("REQUEST_INVALID")

    # This is deliberately the original v1 fingerprint. Runtime policy changes
    # bind through the separate policy fields and never rewrite input identity.
    digest = hashlib.sha256(_json([input, max_rounds, max_tool_calls]).encode()).hexdigest()
    if extended:
        digest = hashlib.sha256(_json([input, max_rounds, max_tool_calls, extension_id,
                                      action_validator is not None, progress_evaluator is not None,
                                      deadline_ms]).encode()).hexdigest()
    policy, loaded, entry_started = await _load_entry(client, key, schema, timeout)
    limits = copy.deepcopy(policy["limits"])
    effective_rounds = min(max_rounds, limits["max_rounds"])
    effective_tool_calls = min(max_tool_calls, limits["max_tool_calls"])
    deadline_default = policy["server_time_ms"] + limits["max_elapsed_seconds"] * 1000
    if deadline_ms is not None:
        deadline_default = min(deadline_default, deadline_ms)

    state = {"version": "harness-loop/v1", "input_hash": digest, "phase": "model",
             "round": 0, "tool_count": 0, "messages": messages, "pending": [],
             "loop_policy_hash": policy["policy_hash"], "loop_limits": copy.deepcopy(limits),
             "loop_deadline_ms": deadline_default, "tool_repeats": {}, "repeat_counted_call_id": ""}
    if extended:
        state.update(version="harness-loop/v2", extension_id=extension_id,
                     model_receipts=[], observations=[])
    validate_runtime_recovery_checkpoint("harness", key, schema, loaded)
    revision = 0
    checkpoint = loaded.get("checkpoint")
    if checkpoint is None:
        authorize_runtime_recovery_start("harness", key, schema, digest)
    if checkpoint is not None:
        if (not isinstance(checkpoint, dict) or type(checkpoint.get("revision")) is not int
                or checkpoint["revision"] < 1):
            raise _stop("HARNESS_STATE_REJECTED")
        previous = checkpoint.get("value")
        if (not isinstance(previous, dict) or previous.get("version") != state["version"]
                or previous.get("input_hash") != digest):
            raise _stop("HARNESS_STATE_REJECTED")
        revision, state = checkpoint["revision"], copy.deepcopy(previous)

    if extended:
        if (state.get("extension_id") != extension_id
                or not isinstance(state.get("model_receipts"), list) or len(state["model_receipts"]) > max_rounds
                or not isinstance(state.get("observations"), list) or len(state["observations"]) != state.get("tool_count")
                or any(not isinstance(item, dict) for item in state["model_receipts"] + state["observations"])):
            raise _stop("HARNESS_STATE_REJECTED")

    phase = state.get("phase")
    if (phase not in ("model", "model_dispatch", "tool", "approval_required", "tool_dispatch",
                      "done", "limit_error", "policy_rejected", "legacy_stop")
            or type(state.get("round")) is not int or not 0 <= state["round"] <= 8
            or type(state.get("tool_count")) is not int or not 0 <= state["tool_count"] <= 16
            or not isinstance(state.get("pending"), list) or len(state["pending"]) > 16
            or not isinstance(state.get("messages"), list) or not state["messages"]):
        raise _stop("HARNESS_STATE_REJECTED")
    for operation in state["pending"]:
        if (not isinstance(operation, dict) or not isinstance(operation.get("name"), str)
                or not operation["name"] or len(operation["name"].encode()) > 128
                or not isinstance(operation.get("call_id"), str) or not operation["call_id"]
                or not isinstance(operation.get("model_call_id"), str) or not operation["model_call_id"]
                or not isinstance(operation.get("payload"), dict)):
            raise _stop("HARNESS_STATE_REJECTED")

    present_policy_fields = [field in state for field in _POLICY_STATE_FIELDS]
    if any(present_policy_fields) and not all(present_policy_fields):
        raise _stop("HARNESS_STATE_REJECTED")
    legacy_state = not any(present_policy_fields)
    legacy_history_valid = True
    legacy_repeats = {}
    if legacy_state:
        if state["tool_count"] > 0:
            if phase not in ("model_dispatch", "tool_dispatch"):
                raise _stop("HARNESS_STATE_REJECTED")
            legacy_history_valid = False
    policy_mismatch = False
    if not legacy_state:
        saved_limits = state.get("loop_limits")
        repeats = state.get("tool_repeats")
        marker = state.get("repeat_counted_call_id")
        if (not isinstance(state.get("loop_policy_hash"), str)
                or re.fullmatch(r"[0-9a-f]{64}", state["loop_policy_hash"]) is None
                or type(state.get("loop_deadline_ms")) is not int
                or not 0 < state["loop_deadline_ms"] <= (1 << 53) - 1
                or not isinstance(saved_limits, dict)
                or set(saved_limits) != {"max_rounds", "max_tool_calls", "max_repeated_calls",
                                         "max_elapsed_seconds", "limit_behavior"}
                or not isinstance(repeats, dict) or len(repeats) > 16
                or not isinstance(marker, str) or len(marker.encode("utf-8")) > 128):
            raise _stop("HARNESS_STATE_REJECTED")
        for field, minimum, maximum in (("max_rounds", 1, 8), ("max_tool_calls", 1, 16),
                                        ("max_repeated_calls", 1, 4), ("max_elapsed_seconds", 10, 3600)):
            if type(saved_limits.get(field)) is not int or not minimum <= saved_limits[field] <= maximum:
                raise _stop("HARNESS_STATE_REJECTED")
        if saved_limits.get("limit_behavior") not in ("error", "incomplete"):
            raise _stop("HARNESS_STATE_REJECTED")
        for semantic_hash, count in repeats.items():
            if (not isinstance(semantic_hash, str) or re.fullmatch(r"[0-9a-f]{64}", semantic_hash) is None
                    or type(count) is not int or not 1 <= count <= 16):
                raise _stop("HARNESS_STATE_REJECTED")
        if marker and (phase not in ("tool_dispatch", "approval_required") or not state["pending"]
                       or state["pending"][0].get("call_id") != marker):
            raise _stop("HARNESS_STATE_REJECTED")
        if phase in ("tool_dispatch", "approval_required") and (not marker or not state["pending"]):
            raise _stop("HARNESS_STATE_REJECTED")
        policy_mismatch = (state["loop_policy_hash"] != policy["policy_hash"] or saved_limits != limits)

    if "prompt_template_hash" in input:
        expected_prompt_hash = input["prompt_template_hash"]
        if not isinstance(expected_prompt_hash, str) or not expected_prompt_hash:
            raise _stop("HARNESS_CONTEXT_REJECTED")
        if "prompt_hash" in state and state["prompt_hash"] != expected_prompt_hash:
            raise _stop("HARNESS_CONTEXT_REJECTED")

    async def save(*, force=False):
        nonlocal revision
        if revision >= 63:
            raise _stop("HARNESS_STATE_LIMIT")
        remaining = remaining_seconds()
        save_timeout = min(float(timeout), remaining) if remaining > 0 else min(float(timeout), 5.0)
        if force and remaining <= 0:
            save_timeout = min(float(timeout), 5.0)
        receipt = await client.save_checkpoint("harness", key, schema, copy.deepcopy(state),
                                              revision, f"loop-{revision + 1}", timeout=save_timeout)
        record_runtime_recovery_checkpoint_save("harness", key, schema, revision, receipt)
        if receipt.get("checkpoint", {}).get("revision") != revision + 1:
            raise _stop("HARNESS_STATE_REJECTED")
        revision += 1

    def remaining_seconds():
        deadline = state.get("loop_deadline_ms", deadline_default)
        service_remaining = (deadline - policy["server_time_ms"]) / 1000.0
        local_elapsed = max(0.0, time.monotonic() - entry_started)
        return service_remaining - local_elapsed

    async def bind_legacy_state():
        state.update(loop_policy_hash=policy["policy_hash"], loop_limits=copy.deepcopy(limits),
                     loop_deadline_ms=deadline_default, tool_repeats=copy.deepcopy(legacy_repeats),
                     repeat_counted_call_id="")
        if state.get("phase") == "approval_required" and state.get("pending"):
            operation = state["pending"][0]
            semantic_hash = _tool_semantic_digest(operation["name"], operation["payload"])
            state["tool_repeats"][semantic_hash] = state["tool_repeats"].get(semantic_hash, 0) + 1
            state["repeat_counted_call_id"] = operation["call_id"]

    async def finish_limit(reason, previous=None):
        state.pop("model_request", None)
        state.pop("limit_after_pending", None)
        state.update(phase="limit_error" if limits["limit_behavior"] == "error" else "done",
                     pending=[], repeat_counted_call_id="",
                     output=_limit_output(previous if previous is not None else state.get("output"), reason))
        if limits["limit_behavior"] == "error":
            state["limit_finish_reason"] = reason
        await save(force=True)
        if limits["limit_behavior"] == "error":
            raise _stop("HARNESS_LIMIT_EXCEEDED")
        raise _HarnessLimitHandled()

    async def require_time():
        if remaining_seconds() <= 0:
            await finish_limit("elapsed_limit")

    def live_timeout():
        remaining = remaining_seconds()
        return min(float(timeout), max(0.001, remaining))

    def receipt_timeout():
        remaining = remaining_seconds()
        return min(float(timeout), 5.0, remaining) if remaining > 0 else min(float(timeout), 5.0)

    async def skills(initial=False):
        prior = state.get("skill_bindings", {})
        if not initial and (not isinstance(prior, dict) or len(prior) != len(skill_requests)):
            raise _stop("HARNESS_SKILL_REJECTED")
        bindings, disclosures = {}, []

        async def load(request, section):
            await require_time()
            receipt = await client._post("/internal/skill/load", {
                "skill_id": request["skill_id"], "section": section,
            }, live_timeout())
            value = receipt.get("skill")
            if (not isinstance(value, dict) or value.get("version") != "skill-disclosure/v1"
                    or value.get("skill_id") != request["skill_id"]
                    or value.get("instruction_trust") != "untrusted_data"
                    or not _skill_identifier(value.get("version_id")) or not isinstance(value.get("digest"), str)):
                raise _stop("HARNESS_SKILL_REJECTED")
            try:
                if len(value["digest"]) != 64 or len(bytes.fromhex(value["digest"])) != 32 or bytes.fromhex(value["digest"]).hex() != value["digest"]:
                    raise ValueError()
            except ValueError:
                raise _stop("HARNESS_SKILL_REJECTED")
            if section and (value.get("section") != section or not isinstance(value.get("content"), str)
                            or not value["content"] or len(value["content"].encode()) > 16384):
                raise _stop("HARNESS_SKILL_REJECTED")
            return value, {"version_id": value["version_id"], "digest": value["digest"]}

        for request in skill_requests:
            summary, binding = await load(request, "")
            if not initial and prior.get(request["skill_id"]) != binding:
                raise _stop("HARNESS_SKILL_VERSION_CHANGED")
            bindings[request["skill_id"]] = binding
            if initial:
                disclosures.append(summary)
                for section in request.get("sections", []):
                    content, selected = await load(request, section)
                    if selected != binding:
                        raise _stop("HARNESS_SKILL_VERSION_CHANGED")
                    disclosures.append(content)
        if initial:
            content = _json({"type": "skill_instructions", "instruction_trust": "untrusted_data", "skills": disclosures})
            if len(content.encode()) > 16384:
                raise _stop("HARNESS_SKILL_CONTEXT_LIMIT")
            state["skill_bindings"] = bindings
            state["messages"].append({"role": "user", "content": content})

    if legacy_state and phase not in ("model_dispatch", "tool_dispatch", "legacy_stop"):
        await bind_legacy_state()
        await save(force=True)

    settled_dispatch = False
    if skill_requests and revision == 0:
        try:
            await skills(initial=True)
        except _HarnessLimitHandled:
            pass

    def step_key(step_phase):
        raw = json.dumps([operation_key, state["round"], step_phase], ensure_ascii=False, separators=(",", ":"))
        return "function-" + hashlib.sha256(raw.encode()).hexdigest()

    while True:
        phase = state["phase"]
        if policy_mismatch and phase not in ("model_dispatch", "tool_dispatch"):
            if settled_dispatch:
                state.update(phase="policy_rejected", pending=[], repeat_counted_call_id="")
                state.pop("model_request", None)
                await save(force=True)
            raise _stop("HARNESS_POLICY_REJECTED")
        if phase == "policy_rejected":
            raise _stop("HARNESS_POLICY_REJECTED")
        if phase == "limit_error":
            raise _stop("HARNESS_LIMIT_EXCEEDED")
        if phase == "legacy_stop":
            raise _stop("HARNESS_STATE_REJECTED")
        if phase == "done":
            output = state.get("output", {})
            status = "incomplete" if output.get("completion_status") == "incomplete" else "completed"
            if status == "completed":
                await complete_runtime_recovery_step("harness", key, schema)
            response = {"status": status, "output": output}
            if extended:
                response["execution"] = {"version": "harness-execution/v2", "extension_id": extension_id,
                    "deadline_ms": state["loop_deadline_ms"], "decision_count": len(state["model_receipts"]),
                    "tool_count": state["tool_count"], "model_receipts": copy.deepcopy(state["model_receipts"]),
                    "observations": copy.deepcopy(state["observations"])}
            return response

        if phase not in ("model_dispatch", "tool_dispatch"):
            try:
                if state.get("limit_after_pending") == "tool_limit" and not state.get("pending"):
                    await finish_limit("tool_limit")
                await require_time()
                if skill_requests:
                    await skills()
            except _HarnessLimitHandled:
                continue

        if phase in ("model", "model_dispatch"):
            recovering = phase == "model_dispatch"
            if revision >= 62:
                raise _stop("HARNESS_STATE_LIMIT")
            if not recovering:
                if state["round"] >= effective_rounds:
                    try:
                        await finish_limit("round_limit")
                    except _HarnessLimitHandled:
                        continue
                try:
                    await require_time()
                except _HarnessLimitHandled:
                    continue
                prepared = await client.prepare_context(copy.deepcopy(state["messages"]),
                                                        current.get("function_names"), timeout=live_timeout())
                if (not isinstance(prepared.get("messages"), list) or not prepared["messages"]
                        or not prepared.get("prompt_template_hash") or not prepared.get("source_hash")
                        or ("prompt_template_hash" in input and (
                            not isinstance(input["prompt_template_hash"], str)
                            or not input["prompt_template_hash"]
                            or input["prompt_template_hash"] != prepared["prompt_template_hash"]))
                        or (state.get("prompt_hash") and state["prompt_hash"] != prepared["prompt_template_hash"])):
                    raise _stop("HARNESS_CONTEXT_REJECTED")
                current.update(messages=prepared["messages"], idempotency_key=step_key("model"),
                               prompt_template_hash=prepared["prompt_template_hash"])
                if prepared.get("model_route_execution") == "model-route-execution/v1":
                    current["deadline_ms"] = state.get("loop_deadline_ms", deadline_default)
                if state.get("skill_bindings"):
                    current["skill_bindings"] = copy.deepcopy(state["skill_bindings"])
                state.update(phase="model_dispatch", prompt_hash=prepared["prompt_template_hash"],
                             context_source_hash=prepared["source_hash"], model_request=copy.deepcopy(current))
                await save()
                if remaining_seconds() <= 0:
                    state.update(phase="model")
                    state.pop("model_request", None)
                    await save(force=True)
                    try:
                        await finish_limit("elapsed_limit")
                    except _HarnessLimitHandled:
                        continue
            request = state.get("model_request")
            if (not isinstance(request, dict) or request.get("idempotency_key") != step_key("model")
                    or not state.get("prompt_hash") or request.get("prompt_template_hash") != state["prompt_hash"]):
                raise _stop("HARNESS_STATE_REJECTED")
            call_timeout = receipt_timeout() if recovering else live_timeout()
            if not recovering and remaining_seconds() <= 0:
                state.update(phase="model")
                state.pop("model_request", None)
                await save(force=True)
                try:
                    await finish_limit("elapsed_limit")
                except _HarnessLimitHandled:
                    continue
            try:
                result = await client._post("/internal/model/receipt" if recovering else "/internal/model/generate",
                                            copy.deepcopy(request), call_timeout)
            except GatewayError as exc:
                if exc.code != "MODEL_BUDGET_EXCEEDED":
                    raise
                if legacy_state and not all(field in state for field in _POLICY_STATE_FIELDS):
                    await bind_legacy_state()
                state.update(phase="done", pending=[], repeat_counted_call_id="",
                             output=_budget_output(state.get("output")))
                state.pop("model_request", None)
                settled_dispatch = recovering
                await save(force=True)
                continue
            if recovering:
                if (result.get("version") != "model-receipt/v1"
                        or result.get("idempotency_key") != request["idempotency_key"]):
                    raise _stop("MODEL_RECEIPT_REJECTED")
                if result.get("status") != "completed":
                    raise _stop("HARNESS_RECONCILIATION_REQUIRED")
                result = result.get("receipt")
                if not isinstance(result, dict):
                    raise _stop("MODEL_RECEIPT_REJECTED")
                settled_dispatch = True
            if legacy_state and not legacy_history_valid:
                state.update(phase="legacy_stop", pending=[],
                             output=_budget_output(result, "legacy_history_unavailable"),
                             legacy_stop_reason="repeat_history_unavailable")
                state.pop("model_request", None)
                await save(force=True)
                raise _stop("HARNESS_STATE_REJECTED")
            if legacy_state and not all(field in state for field in _POLICY_STATE_FIELDS):
                await bind_legacy_state()
            state.pop("model_request", None)
            if extended:
                state["model_receipts"].append({"idempotency_key": request["idempotency_key"],
                                               "receipt": copy.deepcopy(result)})
            calls = result.get("tool_calls")
            if _budget_exhausted(result) and isinstance(calls, list) and calls:
                state.update(phase="done", pending=[], repeat_counted_call_id="",
                             output=_budget_output(result))
                await save(force=True)
                continue
            if calls is None or calls == [] or result.get("completion_status") == "incomplete":
                if result.get("completion_status") == "tool_calls":
                    raise _stop("FUNCTION_RESPONSE_INVALID")
                state.update(phase="done", output=result)
                await save(force=True)
                continue
            if not isinstance(calls, list):
                raise _stop("FUNCTION_RESPONSE_INVALID")
            bindings, seen, pending_operations = result.get("function_bindings", {}), set(), []
            if not isinstance(bindings, dict):
                raise _stop("FUNCTION_RESPONSE_INVALID")
            for call in calls:
                function = call.get("function") if isinstance(call, dict) else None
                if not isinstance(function, dict):
                    raise _stop("FUNCTION_RESPONSE_INVALID")
                tool, model_id = bindings.get(function.get("name")), call.get("id")
                try:
                    payload = json.loads(function.get("arguments", ""),
                                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                except (ValueError, TypeError):
                    raise _stop("FUNCTION_RESPONSE_INVALID") from None
                if (not isinstance(tool, str) or not tool or len(tool.encode()) > 128
                        or not isinstance(model_id, str) or not model_id or len(model_id.encode()) > 128
                        or model_id in seen or not isinstance(payload, dict)):
                    raise _stop("FUNCTION_RESPONSE_INVALID")
                seen.add(model_id)
                pending_operations.append({"name": tool, "call_id": step_key(model_id),
                                           "payload": payload, "model_call_id": model_id})
            if action_validator is not None:
                # Validate the whole proposed batch before invoking its first
                # member: a later forbidden operation cannot be hidden behind
                # an earlier allowed read.
                view = {"round": state["round"], "tool_count": state["tool_count"],
                        "observations": copy.deepcopy(state["observations"])}
                for operation in pending_operations:
                    if action_validator(copy.deepcopy(operation), copy.deepcopy(view)) is not True:
                        state.update(phase="done", pending=[], repeat_counted_call_id="",
                                     output=_limit_output(result, "action_rejected"))
                        await save(force=True)
                        raise _stop("HARNESS_ACTION_REJECTED")
            if not policy_mismatch and state["round"] >= effective_rounds - 1:
                try:
                    await finish_limit("round_limit", result)
                except _HarnessLimitHandled:
                    continue
            available = effective_tool_calls - state["tool_count"]
            if not policy_mismatch and available <= 0:
                try:
                    await finish_limit("tool_limit", result)
                except _HarnessLimitHandled:
                    continue
            state["messages"].append({"role": "assistant", "content": result.get("text", ""), "tool_calls": calls})
            if policy_mismatch:
                state.update(phase="tool", pending=pending_operations,
                             output=_budget_output(result, "tools_pending"))
            else:
                state.update(phase="tool", pending=pending_operations[:available],
                             output=_budget_output(result, "tools_pending"))
                if len(pending_operations) > available:
                    state["limit_after_pending"] = "tool_limit"
                else:
                    state.pop("limit_after_pending", None)
            await save(force=True)
        elif phase in ("tool", "approval_required", "tool_dispatch"):
            recovering = phase == "tool_dispatch"
            if revision >= 62:
                raise _stop("HARNESS_STATE_LIMIT")
            if not state.get("pending"):
                raise _stop("HARNESS_STATE_REJECTED")
            operation = copy.deepcopy(state["pending"][0])
            pending_view = {**operation, "run_id": getattr(client._context, "task_id", "")}
            if phase == "approval_required" and not confirmation_token:
                return {"status": "approval_required", "pending": pending_view}
            original_phase = phase
            if not recovering:
                if action_validator is not None:
                    view = {"round": state["round"], "tool_count": state["tool_count"],
                            "observations": copy.deepcopy(state["observations"])}
                    if action_validator(copy.deepcopy(operation), view) is not True:
                        raise _stop("HARNESS_ACTION_REJECTED")
                if state["tool_count"] >= effective_tool_calls:
                    try:
                        await finish_limit("tool_limit")
                    except _HarnessLimitHandled:
                        continue
                semantic_hash = _tool_semantic_digest(operation["name"], operation["payload"])
                count = state["tool_repeats"].get(semantic_hash, 0)
                already_counted = state.get("repeat_counted_call_id") == operation["call_id"]
                if not already_counted and count >= limits["max_repeated_calls"]:
                    try:
                        await finish_limit("repeated_tool_limit")
                    except _HarnessLimitHandled:
                        continue
                if not already_counted:
                    state["tool_repeats"][semantic_hash] = count + 1
                    state["repeat_counted_call_id"] = operation["call_id"]
                state["phase"] = "tool_dispatch"
                await save()
                if remaining_seconds() <= 0:
                    state["phase"] = original_phase
                    await save(force=True)
                    try:
                        await finish_limit("elapsed_limit")
                    except _HarnessLimitHandled:
                        continue
            command = {field: operation[field] for field in ("name", "call_id", "payload")}
            if confirmation_token:
                command["confirmation_token"] = confirmation_token
            confirmation_token = ""
            call_timeout = receipt_timeout() if recovering else live_timeout()
            if not recovering and remaining_seconds() <= 0:
                state["phase"] = original_phase
                await save(force=True)
                try:
                    await finish_limit("elapsed_limit")
                except _HarnessLimitHandled:
                    continue
            try:
                receipt = await client._post("/internal/tool/receipt" if recovering else "/internal/tool/invoke",
                                             command, call_timeout)
            except GatewayError as exc:
                if exc.code == "MODEL_BUDGET_EXCEEDED":
                    if legacy_state and not all(field in state for field in _POLICY_STATE_FIELDS):
                        await bind_legacy_state()
                    state.update(phase="done", pending=[], repeat_counted_call_id="",
                                 output=_budget_output(state.get("output")))
                    settled_dispatch = recovering
                    await save(force=True)
                    continue
                if exc.code != "TOOL_CONFIRMATION_REQUIRED":
                    raise
                if not recovering:
                    state["phase"] = "approval_required"
                    await save(force=True)
                return {"status": "approval_required", "pending": pending_view}
            if recovering:
                if (receipt.get("version") != "tool-receipt/v1"
                        or receipt.get("tool_name") != operation["name"]
                        or receipt.get("call_id") != operation["call_id"]):
                    raise _stop("TOOL_RECEIPT_REJECTED")
                if receipt.get("status") != "completed":
                    raise _stop("HARNESS_RECONCILIATION_REQUIRED")
                receipt = receipt.get("receipt")
                if not isinstance(receipt, dict):
                    raise _stop("TOOL_RECEIPT_REJECTED")
                settled_dispatch = True
            observation = _tool_context(receipt, operation)
            if legacy_state:
                state["messages"].append({"role": "tool", "tool_call_id": operation["model_call_id"],
                                          "content": _json(observation)})
                state["tool_count"] += 1
                state["pending"] = []
                state["phase"] = "legacy_stop"
                state["legacy_stop_reason"] = "legacy_dispatch_receipt_consumed"
                if legacy_history_valid:
                    await bind_legacy_state()
                    semantic_hash = _tool_semantic_digest(operation["name"], operation["payload"])
                    state["tool_repeats"][semantic_hash] = state["tool_repeats"].get(semantic_hash, 0) + 1
                await save(force=True)
                raise _stop("HARNESS_STATE_REJECTED")
            if legacy_state and not all(field in state for field in _POLICY_STATE_FIELDS):
                await bind_legacy_state()
                semantic_hash = _tool_semantic_digest(operation["name"], operation["payload"])
                state["tool_repeats"][semantic_hash] = state["tool_repeats"].get(semantic_hash, 0) + 1
            state["messages"].append({"role": "tool", "tool_call_id": operation["model_call_id"],
                                      "content": _json(observation)})
            state["tool_count"] += 1
            if extended:
                state["observations"].append({"operation": copy.deepcopy(operation),
                                               "observation": copy.deepcopy(observation)})
            state["repeat_counted_call_id"] = ""
            state["pending"].pop(0)
            state["phase"] = "tool"
            if not state["pending"]:
                state["round"] += 1
                state["phase"] = "model"
            if progress_evaluator is not None:
                view = {"round": state["round"], "tool_count": state["tool_count"],
                        "observations": copy.deepcopy(state["observations"])}
                outcome = progress_evaluator(copy.deepcopy(observation), view)
                if outcome is not None:
                    if not isinstance(outcome, dict) or outcome.get("completion_status") not in ("completed", "incomplete"):
                        raise _stop("HARNESS_PROGRESS_REJECTED")
                    state.update(phase="done", pending=[], output=copy.deepcopy(outcome))
            await save(force=True)
        else:
            raise _stop("HARNESS_STATE_REJECTED")
