import copy
import hashlib
import json
import time
from types import SimpleNamespace

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.harness import _tool_semantic_digest


class Fixture(CapabilityGatewayClient):
    def __init__(self, unknown=False, denied=False, policy=None, repeat_tool=False):
        self._context = SimpleNamespace(task_id="trusted-run")
        self.checkpoint = None
        self.revision = self.models = self.effects = self.contexts = 0
        self.unknown, self.denied = unknown, denied
        self.queries = 0
        self.receipt = None
        self.paths = []
        self.policy_requests = []
        self.fail_receipt_save = False
        self.fail_model_save = False
        self.model_queries = 0
        self.model_status = "completed"
        self.model_receipts = {}
        self.policy = {"max_rounds": 8, "max_tool_calls": 16, "max_repeated_calls": 1,
                       "max_elapsed_seconds": 300, "limit_behavior": "error"}
        if policy:
            self.policy.update(policy)
        self.repeat_tool = repeat_tool

    async def load_checkpoint(self, *args, **kwargs):
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def save_checkpoint(self, namespace, key, schema, value, expected, operation_key, **kwargs):
        if self.fail_model_save and value["phase"] == "tool":
            self.fail_model_save = False
            raise GatewayError("STATE_UNAVAILABLE", "fixed")
        if self.fail_receipt_save and value["phase"] == "model" and value["tool_count"] == 1:
            self.fail_receipt_save = False
            raise GatewayError("STATE_UNAVAILABLE", "fixed")
        assert expected == self.revision
        assert operation_key == f"loop-{expected + 1}"
        self.revision += 1
        self.checkpoint = {"revision": self.revision, "value": copy.deepcopy(value)}
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def prepare_context(self, messages, names, **kwargs):
        self.contexts += 1
        if self.denied:
            raise GatewayError("CAPABILITY_DENIED", "fixed")
        return {"messages": [{"role": "system", "content": "approved"}, *messages],
                "prompt_template_hash": "approved-hash", "source_hash": "source-hash"}

    async def _post(self, path, command, timeout):
        self.paths.append(path)
        if path.endswith("/internal/runtime/harness-policy"):
            self.policy_requests.append((path, copy.deepcopy(command)))
            canonical = json.dumps(self.policy, sort_keys=True, separators=(",", ":"))
            return {"version": "harness-policy/v1", "policy_hash": hashlib.sha256(canonical.encode()).hexdigest(),
                    "server_time_ms": int(time.time() * 1000), "limits": copy.deepcopy(self.policy)}
        if path.endswith("model/receipt"):
            self.model_queries += 1
            return {"version":"model-receipt/v1", "idempotency_key":command["idempotency_key"], "status":self.model_status,
                    "receipt":copy.deepcopy(self.model_receipts[command["idempotency_key"]])}
        if path.endswith("tool/receipt"):
            self.queries += 1
            if command.get("confirmation_token") != "opaque":
                raise GatewayError("TOOL_CONFIRMATION_REQUIRED", "fixed")
            return {"version": "tool-receipt/v1", "tool_name": command["name"], "call_id": command["call_id"],
                    "status": "unknown" if self.unknown else "completed", "receipt": copy.deepcopy(self.receipt)}
        if path.endswith("model/generate"):
            assert command["messages"][0]["content"] == "approved"
            assert command["prompt_template_hash"] == "approved-hash"
            self.models += 1
            if self.models == 1 or (self.repeat_tool and self.models == 2):
                call_id = f"call-{self.models}"
                result = {"text": "", "completion_status": "tool_calls", "function_bindings": {"update": "ticket.update"},
                        "tool_calls": [{"id": call_id, "function": {"name": "update", "arguments": '{"sequence":9007199254740993}'}}]}
                self.model_receipts[command["idempotency_key"]] = copy.deepcopy(result)
                return result
            return {"text": "complete"}
        assert command["payload"]["sequence"] == 9007199254740993
        if command.get("confirmation_token") != "opaque":
            raise GatewayError("TOOL_CONFIRMATION_REQUIRED", "fixed")
        self.effects += 1
        if self.unknown:
            raise GatewayError("TOOL_RESULT_UNKNOWN", "fixed")
        self.receipt = {"observation": {"version": "runtime-observation/v1", "tool_name": "ticket.update",
                                "call_id": command["call_id"], "status": "succeeded", "effect": "completed",
                                "instruction_trust": "untrusted_data", "context_output": {"ok": True}}}
        return copy.deepcopy(self.receipt)


def input():
    return {"messages": [{"role": "user", "content": "resolve"}], "idempotency_key": "operation"}


@pytest.mark.asyncio
async def test_harness_policy_is_a_read_only_exact_empty_post_with_bounded_values():
    client = Fixture()
    policy = await client.load_harness_policy()
    assert policy["version"] == "harness-policy/v1"
    assert client.policy_requests == [("/internal/runtime/harness-policy", {})]
    invalid = Fixture(policy={"max_elapsed_seconds": 9})
    with pytest.raises(GatewayError, match="HARNESS_POLICY_REJECTED"):
        await invalid.load_harness_policy()


def test_tool_semantic_digest_matches_go_integer_and_string_encoding():
    payload = {"large": 9007199254740993, "text": "<&>\u2028"}
    canonical = (b'["x",{"large":9007199254740993,'
                 b'"text":"\\u003c\\u0026\\u003e\\u2028"}]')
    assert _tool_semantic_digest("x", payload) == hashlib.sha256(canonical).hexdigest()


@pytest.mark.asyncio
async def test_approval_resume_preserves_operation_and_replays_only_saved_result():
    client = Fixture()
    pending = await client.run_harness(input(), key="loop")
    assert pending["status"] == "approval_required"
    assert pending["pending"]["run_id"] == "trusted-run"
    saved = client.checkpoint["value"]
    assert set(("loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats",
                "repeat_counted_call_id")) <= set(saved)
    assert saved["repeat_counted_call_id"] == saved["pending"][0]["call_id"]
    assert sum(saved["tool_repeats"].values()) == 1
    assert (await client.run_harness(input(), key="loop")) == pending
    assert sum(client.checkpoint["value"]["tool_repeats"].values()) == 1
    assert client.models == 1 and client.effects == 0
    result = await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert result["status"] == "completed"
    assert (client.models, client.effects, client.contexts) == (2, 1, 2)
    assert await client.run_harness(input(), key="loop") == result
    assert (client.models, client.effects, client.contexts) == (2, 1, 2)
    assert "opaque" not in json.dumps(client.checkpoint)
    changed = input(); changed["idempotency_key"] = "other"
    with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
        await client.run_harness(changed, key="loop")


@pytest.mark.asyncio
async def test_unknown_effect_requires_coordination_without_redispatch():
    client = Fixture(unknown=True)
    with pytest.raises(GatewayError, match="TOOL_RESULT_UNKNOWN"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    with pytest.raises(GatewayError, match="HARNESS_RECONCILIATION_REQUIRED"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert client.effects == client.models == 1


@pytest.mark.asyncio
async def test_context_denied_before_model_and_dispatch_checkpoint():
    client = Fixture(denied=True)
    with pytest.raises(GatewayError, match="CAPABILITY_DENIED"):
        await client.run_harness(input(), key="loop")
    assert client.revision == client.models == client.effects == 0


@pytest.mark.asyncio
async def test_saved_tool_receipt_recovers_checkpoint_failure_without_execution():
    client = Fixture(); client.fail_receipt_save = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert client.checkpoint["value"]["phase"] == "tool_dispatch"
    assert client.effects == 1
    assert client.paths.count("/internal/tool/invoke") == 1
    pending = await client.run_harness(input(), key="loop")
    assert pending["status"] == "approval_required" and client.effects == 1
    assert client.checkpoint["value"]["phase"] == "tool_dispatch"
    assert client.paths[-1] == "/internal/tool/receipt"
    assert client.paths.count("/internal/tool/invoke") == 1
    assert client.paths.count("/internal/tool/receipt") == 1
    result = await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert result["status"] == "completed"
    assert (client.models, client.effects, client.queries) == (2, 1, 2)
    assert client.paths.count("/internal/tool/invoke") == 1
    assert client.paths.count("/internal/tool/receipt") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "not_found", "running", "failed", "reconcile"])
async def test_model_receipt_recovery_never_repeats_model_or_context(status):
    client = Fixture(); client.fail_model_save = True; client.model_status = status
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    if status == "completed":
        result = await client.run_harness(input(), key="loop", confirmation_token="opaque")
        assert result["status"] == "completed"
        assert (client.models, client.contexts, client.effects) == (2, 2, 1)
    else:
        with pytest.raises(GatewayError, match="HARNESS_RECONCILIATION_REQUIRED"):
            await client.run_harness(input(), key="loop", confirmation_token="opaque")
        assert (client.models, client.contexts, client.effects) == (1, 1, 0)
    assert client.model_queries == 1


@pytest.mark.asyncio
async def test_repeated_semantic_tool_call_hits_published_limit_without_second_effect():
    client = Fixture(policy={"limit_behavior": "incomplete"}, repeat_tool=True)
    result = await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert result["status"] == "incomplete"
    assert result["output"]["termination_reason"] == "HARNESS_LIMIT_EXCEEDED"
    assert result["output"]["finish_reason"] == "repeated_tool_limit"
    assert client.effects == 1


@pytest.mark.asyncio
async def test_changed_policy_recovers_original_tool_receipt_before_stopping():
    client = Fixture(); client.fail_receipt_save = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    client.policy["max_rounds"] = 7
    with pytest.raises(GatewayError, match="HARNESS_POLICY_REJECTED"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert client.effects == 1 and client.models == 1 and client.queries == 1
    assert client.checkpoint["value"]["phase"] == "policy_rejected"


@pytest.mark.asyncio
async def test_legacy_tool_dispatch_consumes_receipt_then_stops_for_explicit_upgrade():
    client = Fixture(); client.fail_receipt_save = True
    with pytest.raises(GatewayError, match="STATE_UNAVAILABLE"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    for field in ("loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats", "repeat_counted_call_id"):
        client.checkpoint["value"].pop(field, None)
    with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
        await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert client.effects == 1 and client.models == 1
    assert client.checkpoint["value"]["phase"] == "legacy_stop"


@pytest.mark.asyncio
async def test_legacy_consumed_tools_without_repeat_metadata_are_rejected():
    client = Fixture()
    await client.run_harness(input(), key="loop", confirmation_token="opaque")
    for field in ("loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats", "repeat_counted_call_id"):
        client.checkpoint["value"].pop(field, None)
    with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
        await client.run_harness(input(), key="loop")
    assert client.effects == 1 and client.models == 2


@pytest.mark.asyncio
async def test_legacy_approval_checkpoint_is_upgraded_with_one_counted_call():
    client = Fixture()
    pending = await client.run_harness(input(), key="loop")
    for field in ("loop_policy_hash", "loop_limits", "loop_deadline_ms", "tool_repeats", "repeat_counted_call_id"):
        client.checkpoint["value"].pop(field, None)
    assert await client.run_harness(input(), key="loop") == pending
    saved = client.checkpoint["value"]
    assert saved["repeat_counted_call_id"] == saved["pending"][0]["call_id"]
    assert sum(saved["tool_repeats"].values()) == 1
    result = await client.run_harness(input(), key="loop", confirmation_token="opaque")
    assert result["status"] == "completed" and client.effects == 1
