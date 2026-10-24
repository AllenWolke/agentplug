import copy
import pytest
from agent_platform_sdk.reference_authorization import authorize_references, authorize_cached_result
from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.graph_recovery import PublicGraphCheckpointBridge
from test_graph_recovery import request, Client as GraphClient, Graph, CONFIG, recovery
from test_step_workflow import StateClient, Executor, run

def reference(number=1):
    return {"source":"platform-knowledge","provider_knowledge_base_id":"kb",
        "provider_document_id":str(number),"document_version":"v1","doc_id":str(number),"content":"private body"}

class Client:
    def __init__(self): self.calls=[]; self.revoked=False
    async def _post(self,path,body,timeout):
        self.calls.append(copy.deepcopy(body))
        assert path=="/internal/knowledge/references/authorize"
        assert all(set(item)=={"source","provider_knowledge_base_id","provider_document_id","document_version"} for item in body["references"])
        if self.revoked: raise GatewayError("KNOWLEDGE_DOCUMENTS_DENIED","current ACL revoked")
        return {"version":"knowledge-reference-authorization/v1","authorized":True,"reference_count":len(body["references"]),"model_requests_sent":0}

@pytest.mark.asyncio
async def test_cached_reference_authorization_deduplicates_and_uses_bounded_identity_pages_only():
    client=Client(); items=[reference(index) for index in range(199)]
    assert await authorize_cached_result(client,{"answer":{"references":items},"evidence":{"applicable":items}},"kb")
    assert [len(call["references"]) for call in client.calls]==[128,71]
    assert "private body" not in str(client.calls)
    client.revoked=True
    with pytest.raises(GatewayError,match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await authorize_references(client,items,"kb")

@pytest.mark.asyncio
async def test_completed_step_is_reauthorized_before_cached_text_can_leave_workflow():
    state,executor=StateClient(),Executor(); authority=Client()
    original=executor.execute
    async def execute(step,runtime,results):
        result=await original(step,runtime,results); result["output"]["references"]=[reference()]; return result
    executor.execute=execute
    async def revalidate(step,result):return await authorize_cached_result(authority,result["output"],"kb")
    executor.revalidate=revalidate
    await run(state,executor); deadline=state.checkpoint["value"]["deadline_ms"]
    authority.revoked=True
    with pytest.raises(GatewayError,match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await run(state,executor)
    assert executor.calls==1 and executor.recoveries==0 and state.checkpoint["value"]["deadline_ms"]==deadline

@pytest.mark.asyncio
async def test_completed_graph_revocation_denies_before_return_or_further_graph_execution():
    req=request(); client=GraphClient(req); graph=Graph(req); authority=Client(); bridge=PublicGraphCheckpointBridge()
    async def work():
        graph.complete(); graph.snapshot.values["answer"]["references"]=[reference()]; return copy.deepcopy(graph.snapshot.values)
    await bridge.execute(req,client,graph,CONFIG,work,revalidate=lambda value:authorize_cached_result(authority,value,"kb"))
    restored=recovery(req,client); authority.revoked=True; writes=len(client.writes)
    with pytest.raises(GatewayError,match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail("completed graph repeated"),
            revalidate=lambda value:authorize_cached_result(authority,value,"kb"))
    assert graph.calls==[] and len(client.writes)==writes


@pytest.mark.asyncio
async def test_selected_graph_view_checks_current_authority_and_does_not_copy_unconsumed_state():
    req=request(); client=GraphClient(req); graph=Graph(req); authority=Client()
    class Unconsumed:
        def __deepcopy__(self, memo):
            raise AssertionError("unconsumed state must not be copied before projection")
    async def work():
        graph.complete()
        graph.snapshot.values.update(answer={"references":[reference()]}, internal=Unconsumed())
        return graph.snapshot.values
    options=dict(revalidate=lambda value:authorize_cached_result(authority,value,"kb"),
        revalidation_view=lambda value:{"answer":value["answer"]})
    await PublicGraphCheckpointBridge().execute(req,client,graph,CONFIG,work,**options)
    assert len(authority.calls)==1
    req.operation="resume"; req.resume_input={}
    authority.revoked=True; writes=len(client.writes)
    with pytest.raises(GatewayError,match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await PublicGraphCheckpointBridge().execute(req,client,graph,CONFIG,
            lambda:pytest.fail("revoked view reached graph"),**options)
    assert len(client.writes)==writes and len(authority.calls)==2


@pytest.mark.asyncio
@pytest.mark.parametrize("selected",[False,True])
async def test_graph_authorization_callback_cannot_mutate_checkpoint_or_returned_data(selected):
    req=request(); client=GraphClient(req); graph=Graph(req)
    async def work():
        graph.complete(); graph.snapshot.values["answer"]["references"]=[reference()]
        return graph.snapshot.values
    async def check(value):
        value["answer"]["references"][0]["content"]="mutated"
        return True
    options={"revalidation_view":lambda value:{"answer":value["answer"]}} if selected else {}
    result=await PublicGraphCheckpointBridge().execute(req,client,graph,CONFIG,work,revalidate=check,**options)
    assert result["answer"]["references"][0]["content"]=="private body"
    assert graph.snapshot.values["answer"]["references"][0]["content"]=="private body"


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid",["missing-check","non-callable","non-object"])
async def test_graph_view_configuration_never_bypasses_reference_check(invalid):
    from agent_platform_sdk.errors import DomainExecutionError
    req=request(); client=GraphClient(req); graph=Graph(req)
    async def check(value):return True
    async def work():graph.complete();return graph.snapshot.values
    view=3 if invalid=="non-callable" else lambda value:[]
    with pytest.raises(DomainExecutionError):
        await PublicGraphCheckpointBridge().execute(req,client,graph,CONFIG,work,
            revalidate=None if invalid=="missing-check" else check,revalidation_view=view)
    assert not client.cp or client.cp["value"]["phase"]=="dispatch"

@pytest.mark.asyncio
async def test_cached_parent_text_checks_all_siblings_even_when_child_is_still_allowed():
    client=Client(); child=reference(); sibling={key:value for key,value in reference(2).items()
        if key in {"source","provider_knowledge_base_id","provider_document_id","document_version"}}
    child["parent_context"]={"schema_version":"authorized-parent-context/v1","content":"private sibling body",
        "source_documents":[{key:child[key] for key in sibling},sibling]}
    original=client._post
    async def authorize(path,body,timeout):
        result=await original(path,body,timeout)
        if any(item["provider_document_id"]=="2" for item in body["references"]):
            raise GatewayError("KNOWLEDGE_DOCUMENTS_DENIED","sibling ACL revoked")
        return result
    client._post=authorize
    with pytest.raises(GatewayError,match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await authorize_cached_result(client,{"references":[child]},"kb")
    assert [item["provider_document_id"] for item in client.calls[0]["references"]]==["1","2"]
    assert "private sibling body" not in str(client.calls)

@pytest.mark.asyncio
@pytest.mark.parametrize("invalid",["missing-version","missing-parent-proof","wrong-parent-schema","child-omitted"])
async def test_cached_text_cannot_evade_authorization_with_incomplete_identity_or_parent_proof(invalid):
    client=Client(); child=reference()
    if invalid=="missing-version":del child["document_version"]
    else:
        documents=[{key:child[key] for key in ("source","provider_knowledge_base_id","provider_document_id","document_version")}]
        child["parent_context"]={"schema_version":"authorized-parent-context/v1","content":"private sibling body","source_documents":documents}
        if invalid=="missing-parent-proof":del child["parent_context"]["source_documents"]
        if invalid=="wrong-parent-schema":child["parent_context"]["schema_version"]="unverified"
        if invalid=="child-omitted":documents[0]["provider_document_id"]="different"
    with pytest.raises(GatewayError,match="KNOWLEDGE_REFERENCE_AUTHORITY_DENIED"):
        await authorize_cached_result(client,{"references":[child]},"kb")
    assert client.calls==[]
