import base64
import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.models import ExecuteRequest, ExecuteResponse
from agent_platform_sdk.task_registry import ExecutionTaskRegistry
from agent_platform_sdk.tool_workflow import GraphToolApproval, run_tool_operation


def request(revision=1, resume=None):
    claims = base64.urlsafe_b64encode(json.dumps({"execution_revision": revision,
        "lease_token_hash": hashlib.sha256(str(revision).encode()).hexdigest()}).encode()).decode().rstrip("=")
    return ExecuteRequest.model_validate({"protocol_version": "agent-execution/v2", "context_token": "e30." + claims + ".fixture",
        "scope": {"tenant_id": "tenant", "department_id": "department", "application_id": "application",
            "agent_id": "test-agent", "agent_version_id": "version", "agent_instance_id": "instance",
            "installation_id": "installation", "principal_type": "user", "principal_id": "operator",
            "session_id": "session", "run_id": "run", "authorization_epoch": 1, "trace_id": "0" * 32},
        "operation": "resume" if resume else "invoke", "idempotency_key": "operation",
        "input_schema": "schema://test-agent/input/v1", "input": {"batch": "batch"}, "resume_input": resume})


class Client:
    def __init__(self):
        self._context = context(request())
        self.heads, self.calls, self.receipts = {}, [], {}
        self.execution_revision = 1
        self.unknown = False

    async def validate_current_execution(self):
        pass

    async def load_checkpoint(self, namespace, key, schema, **kwargs):
        return {"checkpoint": copy.deepcopy(self.heads.get(key))}

    async def save_checkpoint(self, namespace, key, schema, value, revision, idempotency_key, **kwargs):
        previous = self.heads.get(key)
        assert revision == (previous["revision"] if previous else 0)
        cp = {"schema_id": schema, "revision": revision + 1, "value": copy.deepcopy(value),
            "content_hash": hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(),
            "execution_revision": self.execution_revision}
        self.heads[key] = cp
        return {"checkpoint": copy.deepcopy(cp)}

    async def invoke_tool(self, name, payload, *, call_id, confirmation_token="", **kwargs):
        self.calls.append((name, call_id, confirmation_token))
        if not confirmation_token:
            raise GatewayError("TOOL_CONFIRMATION_REQUIRED", "confirm exact operation")
        if self.unknown:
            raise GatewayError("TOOL_RESULT_UNKNOWN", "unknown write")
        result = {"data": {"saved": payload["value"]}, "observation": {"version": "runtime-observation/v1",
            "tool_name": name, "call_id": call_id, "status": "succeeded", "effect": "completed",
            "instruction_trust": "untrusted_data"}}
        self.receipts[call_id] = result
        return result

    async def _post(self, path, payload, timeout):
        assert path == "/internal/tool/receipt"
        result = self.receipts.get(payload["call_id"])
        return {"version": "tool-receipt/v1", "tool_name": payload["name"], "call_id": payload["call_id"],
                "status": "completed" if result else "not_found", "receipt": result}


def context(req):
    scope = req.scope.model_dump()
    scope["actor_id"], scope["task_id"] = scope.pop("principal_id"), scope.pop("run_id")
    return SimpleNamespace(**scope, idempotency_key=req.idempotency_key,
                           platform_context_token=req.context_token,
                           runtime_policy_id="frozen-policy")


async def pause(registry, bridge, client, req, value=1):
    async def work():
        result = await run_tool_operation(client, "write.record", {"value": value}, key="write-1")
        return ExecuteResponse(run_id="run", status="waiting" if result.get("status") == "approval_required" else "succeeded", output=result)
    response = await registry.execute(req, lambda: bridge.execute(req, client, work))
    return response


def resume_request(response, client, revision=3):
    key = response.handoff.harness_key
    cp = client.heads[key]
    reference = {"namespace": "harness", "key": key, **{field: cp[field] for field in
        ("schema_id", "revision", "content_hash", "execution_revision")}}
    return request(revision, {"confirmation_token": "opaque-confirmation",
                             "handoff": response.handoff.model_dump(), "checkpoint": reference})


@pytest.mark.asyncio
async def test_handoff_requires_real_registry_exit_and_survives_new_bridge():
    registry, client = ExecutionTaskRegistry(), Client()
    bridge, req = GraphToolApproval(registry), request()
    response = await pause(registry, bridge, client, req)
    approved = bridge.finalize_response(req, response)
    assert approved.handoff is not None
    assert approved.handoff.tool_name == "write.record"
    resumed = resume_request(approved, client)
    client.execution_revision = 3
    restarted_registry = ExecutionTaskRegistry()
    restarted = GraphToolApproval(restarted_registry)
    result = await pause(restarted_registry, restarted, client, resumed)
    assert result.status == "succeeded" and result.output["data"] == {"saved": 1}
    assert len(client.calls) == 2
    assert "opaque-confirmation" not in json.dumps(client.heads)
    assert restarted.finalize_response(resumed, result).handoff is None


@pytest.mark.asyncio
async def test_four_approvals_and_business_review_preserve_lastvalue_context():
    from typing import TypedDict
    from langgraph.graph import START, END, StateGraph
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command, interrupt
    from agent_platform_sdk.graph_context import resolve_graph_context
    from agent_platform_sdk.tool_workflow import run_graph_tool

    class State(TypedDict, total=False):
        context: dict
        prepared: int
        review: str
        finished: bool

    client, saver, computed, tokens = Client(), MemorySaver(), [], []
    config = {"configurable": {"thread_id": "four-approvals"}}
    req = request()
    original = vars(context(req)).copy()

    async def compute(state):
        computed.append(1)
        return {"prepared": 1}

    async def writes(state, numbers):
        resolved = resolve_graph_context(SimpleNamespace(**state["context"]))
        assert resolved is client._context
        tokens.append(resolved.platform_context_token)
        for number in numbers:
            await run_graph_tool(client, "write.record", {"value": number}, key=f"write-{number}")
        return {}

    async def first(state):
        return await writes(state, (1, 2))

    async def review(state):
        decision = interrupt({"kind": "business-review"})
        assert decision == {"decision": "approve"}
        return {"review": decision["decision"]}

    async def final(state):
        assert state["review"] == "approve"
        await writes(state, (3, 4))
        return {"finished": True}

    def graph():
        g = StateGraph(State)
        for name, node in (("compute", compute), ("first", first), ("review", review), ("final", final)):
            g.add_node(name, node)
        for before, after in ((START, "compute"), ("compute", "first"), ("first", "review"), ("review", "final"), ("final", END)):
            g.add_edge(before, after)
        return g.compile(checkpointer=saver)

    for revision in (1, 3, 5, 7, 9, 11):
        client._context, client.execution_revision = context(req), revision
        registry = ExecutionTaskRegistry()
        bridge, current_graph = GraphToolApproval(registry), graph()

        async def work():
            command = Command(resume=req.resume_input) if req.operation == "resume" else {"context": original}
            state = await current_graph.ainvoke(command, config)
            assert state["context"] == original
            return ExecuteResponse(run_id="run", status="waiting" if state.get("__interrupt__") else "succeeded",
                                   output={"finished": state.get("finished", False)})

        result = await registry.execute(req, lambda: bridge.execute(req, client, work))
        result = bridge.finalize_response(req, result)
        if revision == 5:
            assert result.handoff is None and result.status == "waiting"
            req = request(7, {"decision": "approve"})
        elif revision < 11:
            assert result.handoff is not None and result.status == "waiting"
            req = resume_request(result, client, revision + 2)
        else:
            assert result.status == "succeeded" and result.output["finished"]
    assert computed == [1]
    assert len(client.calls) == 8 and sum(bool(token) for _, _, token in client.calls) == 4
    assert len(set(tokens)) >= 4
    assert "opaque-confirmation" not in json.dumps(saver.storage, default=str)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["body", "key", "hash", "name", "lease", "boolean_revision"])
async def test_changed_resume_bindings_never_execute(mutation):
    registry, client = ExecutionTaskRegistry(), Client()
    bridge, req = GraphToolApproval(registry), request()
    first = bridge.finalize_response(req, await pause(registry, bridge, client, req))
    resumed = resume_request(first, client)
    if mutation == "body":
        resumed.input["batch"] = "other"
    elif mutation == "key":
        resumed.resume_input["checkpoint"]["key"] = "other"
    elif mutation == "hash":
        resumed.resume_input["checkpoint"]["content_hash"] = "0" * 64
    elif mutation == "name":
        resumed.resume_input["handoff"]["tool_name"] = "other"
    elif mutation == "lease":
        resumed.context_token = req.context_token
    else:
        resumed.resume_input["checkpoint"]["revision"] = True
    with pytest.raises(DomainExecutionError):
        await pause(registry, bridge, client, resumed)
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_unknown_write_only_queries_receipt_and_never_replays():
    registry, client = ExecutionTaskRegistry(), Client()
    bridge, req = GraphToolApproval(registry), request()
    first = bridge.finalize_response(req, await pause(registry, bridge, client, req))
    resumed = resume_request(first, client)
    client.execution_revision, client.unknown = 3, True
    with pytest.raises(GatewayError):
        await pause(registry, bridge, client, resumed)
    assert client.heads["write-1"]["value"]["phase"] == "tool_dispatch"
    with pytest.raises(GatewayError):
        await run_tool_operation(client, "write.record", {"value": 1}, key="write-1")
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_business_wait_or_forged_handoff_does_not_prove_tool_pause():
    registry, client = ExecutionTaskRegistry(), Client()
    bridge, req = GraphToolApproval(registry), request()
    async def work():
        return ExecuteResponse(run_id="run", status="waiting", output={"review": "required"})
    result = await registry.execute(req, lambda: bridge.execute(req, client, work))
    assert bridge.finalize_response(req, result).handoff is None
    assert client.calls == []


@pytest.mark.asyncio
async def test_pause_before_registry_exit_has_no_handoff():
    registry, client = ExecutionTaskRegistry(), Client()
    bridge, req = GraphToolApproval(registry), request()
    async def work():
        output = await run_tool_operation(client, "write.record", {"value": 1}, key="write-1")
        return ExecuteResponse(run_id="run", status="waiting", output=output)
    response = await bridge.execute(req, client, work)
    with pytest.raises(DomainExecutionError) as error:
        bridge.finalize_response(req, response)
    assert error.value.code == "RUN_HANDOFF_UNCONFIRMED"


@pytest.mark.asyncio
async def test_two_graph_approvals_after_rebuild_do_not_recompute_or_repeat_write():
    from typing import TypedDict
    from langgraph.graph import START, END, StateGraph
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command
    from agent_platform_sdk.tool_workflow import run_graph_tool
    class State(TypedDict, total=False):
        prepared: int
        values: list
    client, saver, computed = Client(), MemorySaver(), []
    config = {"configurable": {"thread_id": "scope-test"}}
    async def compute(state):
        computed.append(1)
        return {"prepared": 1}
    async def write(state):
        values=[]
        for number in (1, 2):
            result = await run_graph_tool(client, "write.record", {"value": number}, key=f"write-{number}")
            values.append(result["data"]["saved"])
        return {"values": values}
    def graph():
        g=StateGraph(State)
        g.add_node("compute",compute); g.add_node("write",write)
        g.add_edge(START,"compute"); g.add_edge("compute","write"); g.add_edge("write",END)
        return g.compile(checkpointer=saver)
    req = request()
    for revision in (1,3,5):
        client.execution_revision=revision
        registry=ExecutionTaskRegistry()
        bridge=GraphToolApproval(registry)
        current_graph=graph()
        async def work():
            command=Command(resume=req.resume_input) if req.operation=="resume" else {}
            result=await current_graph.ainvoke(command,config)
            return ExecuteResponse(run_id="run", status="waiting" if result.get("__interrupt__") else "succeeded",
                                   output={"values":result.get("values",[])})
        response=await registry.execute(req,lambda:bridge.execute(req,client,work))
        response=bridge.finalize_response(req,response)
        if revision<5:
            assert response.status=="waiting"
            assert response.handoff.harness_key==f"write-{1 if revision==1 else 2}"
            req=resume_request(response,client,revision+2)
        else:
            assert response.status=="succeeded" and response.output["values"]==[1,2]
    assert computed==[1]
    assert len(client.calls)==4  # two rejected previews, two confirmed writes
    assert sum(bool(token) for _,_,token in client.calls)==2
    assert "opaque-confirmation" not in json.dumps(client.heads)
