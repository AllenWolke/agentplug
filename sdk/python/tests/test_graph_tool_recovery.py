"""Actual LangGraph approval slots survive owner stop and a lost write reply."""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import TypedDict

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import START, END, StateGraph
from langgraph.types import Command

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.graph_recovery import PublicGraphCheckpointBridge
from agent_platform_sdk.recovery_context import checkpoint_state_key
from agent_platform_sdk.task_registry import ExecutionTaskRegistry
from agent_platform_sdk.tool_workflow import GraphToolApproval, graph_tool_resume_input, run_graph_tool
from agent_platform_sdk.models import ExecuteResponse
from agent_platform_sdk.errors import DomainExecutionError
from test_tool_workflow import Client as ToolClient, context, request, resume_request


class Client(ToolClient):
    def __init__(self):
        super().__init__()
        self.lose_reply = False

    async def save_checkpoint(self, *args, **kwargs):
        result = await super().save_checkpoint(*args, **kwargs)
        self.heads[args[1]]["expires_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        return {"checkpoint": copy.deepcopy(self.heads[args[1]])}

    async def load_recovery_checkpoint(self, reference):
        for key, cp in self.heads.items():
            namespace = "graph-runtime" if key == "workflow" else "harness"
            if checkpoint_state_key(self.req.scope, namespace, key) == reference["state_key"]:
                return {"state_key": reference["state_key"], "checkpoint": copy.deepcopy(cp)}
        raise AssertionError("reference not owned")

    async def invoke_tool(self, *args, **kwargs):
        result = await super().invoke_tool(*args, **kwargs)
        if self.lose_reply:
            self.lose_reply = False
            raise GatewayError("TOOL_RESULT_UNKNOWN", "lost reply after actual fixture write")
        return result


def runtime_request(original, client, revision, stopped, approved=None):
    req = request(revision)
    req.input = copy.deepcopy(original.input)
    req.operation = "resume"
    references = []
    for key, cp in client.heads.items():
        namespace = "graph-runtime" if key == "workflow" else "harness"
        references.append({"state_key": checkpoint_state_key(req.scope, namespace, key),
            **{field: cp[field] for field in ("revision", "schema_id", "content_hash", "execution_revision", "expires_at")}})
    references.sort(key=lambda row: row["state_key"])
    req.resume_input = {"version": "runtime-recovery/v1", "origin_operation": "invoke", "reference": {
        "version": "runtime-recovery-stop/v1", "run_id": req.scope.run_id, "stopped_revision": stopped,
        "ready_revision": stopped + 2, "operation": "resume" if approved else "invoke",
        "body_hash": "c" * 64, "policy_hash": "c" * 64,
        "lease_token_hash": hashlib.sha256(str(stopped).encode()).hexdigest(),
        "request_hash": "c" * 64, "resume_input_hash": "c" * 64,
        "source": "sdk-cancel-exit/v1", "checkpoints": references}}
    if approved:
        req.resume_input["confirmation_token"] = approved.resume_input["confirmation_token"]
        req.resume_input["tool_resume"] = {"version": "graph-tool-resume/v1",
            **{field: approved.resume_input[field] for field in ("handoff", "checkpoint")}}
    return req


@pytest.mark.asyncio
@pytest.mark.parametrize("lost_reply", [False, True])
async def test_real_graph_two_approvals_stop_and_receipt_recovery_do_not_rewrite(lost_reply):
    class State(TypedDict, total=False):
        context: dict
        prepared: int
        results: list

    client, saver, computed = Client(), InMemorySaver(), []
    config = {"configurable": {"thread_id": "scope-v2:two-approvals-stop"}}
    async def prepare(state):
        computed.append(1)
        return {"prepared": 1}
    async def write(state):
        values = []
        for number in (1, 2):
            result = await run_graph_tool(client, "write.record", {"value": number}, key=f"write-{number}")
            values.append(result["data"]["saved"])
        return {"results": values}
    def graph():
        builder = StateGraph(State)
        builder.add_node("prepare", prepare); builder.add_node("write", write)
        builder.add_edge(START, "prepare"); builder.add_edge("prepare", "write"); builder.add_edge("write", END)
        return builder.compile(checkpointer=saver)
    original = request(1)
    original.input["policy_snapshot"] = {"content_hash": "c" * 64, "runtime": {"recovery_references": "paged/v1"}}
    async def dispatch(req):
        client.req, client._context = req, context(req)
        client.execution_revision = json.loads(ExecutionLifecycle._identity(req).key)[1]
        registry = ExecutionTaskRegistry()
        approval = GraphToolApproval(registry)
        bridge = PublicGraphCheckpointBridge()
        current = graph()
        async def graph_work():
            payload = (Command(resume=graph_tool_resume_input(req)) if req.operation == "resume"
                       else {"context": vars(context(req))})
            return await current.ainvoke(payload, config)
        async def work():
            result = await bridge.execute(req, client, current, config, graph_work)
            return ExecuteResponse(run_id="run", status="waiting" if result.get("__interrupt__") else "succeeded",
                output={"results": result.get("results", [])})
        response = await registry.execute(req, lambda: approval.execute(req, client, work))
        return approval.finalize_response(req, response)
    first = await dispatch(original)
    assert first.handoff.harness_key == "write-1"
    approved = resume_request(first, client, 3)
    approved.input = copy.deepcopy(original.input)
    # Simulate the confirmed stopped owner before it receives its approved write.
    restored = runtime_request(original, client, 6, 3, approved)
    client.lose_reply = lost_reply
    if lost_reply:
        with pytest.raises(GatewayError, match="lost reply"):
            await dispatch(restored)
        diagnostic = await graph().aget_state(config)
        # LangGraph versions expose a failed task either in `next` or only in
        # `tasks`. Both must retain the original write, never re-run prepare.
        assert set(diagnostic.next) <= {"write"} and any(task.error for task in diagnostic.tasks)
        assert computed == [1]
        assert client.heads["workflow"]["value"]["phase"] == "dispatch"
        restored = runtime_request(original, client, 9, 6)
    second = await dispatch(restored)
    assert second.handoff is not None, (second.model_dump(), client.calls, client.heads)
    assert second.handoff.harness_key == "write-2"
    final_req = resume_request(second, client, client.execution_revision + 2)
    final_req.input = copy.deepcopy(original.input)
    final = await dispatch(final_req)
    assert final.status == "succeeded" and final.output["results"] == [1, 2]
    assert computed == [1]
    confirmed = [(name, call) for name, call, token in client.calls if token]
    assert len(confirmed) == 2 and len(set(confirmed)) == 2
    assert "opaque-confirmation" not in json.dumps(client.heads)
    assert "opaque-confirmation" not in str(list(saver.storage.values()))


@pytest.mark.asyncio
async def test_runtime_tool_marker_without_exact_checkpoint_is_denied_before_work():
    client = Client(); registry = ExecutionTaskRegistry(); bridge = GraphToolApproval(registry)
    from test_tool_workflow import pause
    original = request(1); original.input["policy_snapshot"] = {"content_hash": "c" * 64}
    client.req = original
    first = bridge.finalize_response(original, await pause(registry, bridge, client, original))
    approved = resume_request(first, client, 3)
    restored = runtime_request(original, client, 6, 3, approved)
    restored.resume_input["tool_resume"]["checkpoint"]["content_hash"] = "a" * 64
    client.req, client._context = restored, context(restored)
    with pytest.raises(DomainExecutionError):
        await GraphToolApproval(ExecutionTaskRegistry()).execute(restored, client, lambda: pytest.fail("foreign approval ran"))
    assert len(client.calls) == 1
