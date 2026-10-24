import asyncio,base64,copy,hashlib,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
import pytest
from agent_platform_sdk.models import ExecuteRequest
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.graph_recovery import PublicGraphCheckpointBridge,SCHEMA,NAMESPACE,KEY,business_review
from agent_platform_sdk.recovery_context import checkpoint_state_key

def request(revision=2,lease='a'):
    data=json.loads((Path(__file__).resolve().parents[3]/'contracts/fixtures/execution-v2-request.json').read_text(encoding='utf8'))
    token=base64.urlsafe_b64encode(json.dumps({'execution_revision':revision,'lease_token_hash':lease*64}).encode()).decode().rstrip('=')
    data['context_token']='fixture.'+token+'.fixture';data['input']['policy_snapshot']={'content_hash':'c'*64}
    return ExecuteRequest.model_validate(data)

def context(req):
    values=req.scope.model_dump();values['actor_id']=values.pop('principal_id');values['task_id']=values.pop('run_id')
    values.update(platform_context_token=req.context_token,idempotency_key=req.idempotency_key)
    return SimpleNamespace(**values)

class Client:
    def __init__(self,req):self._context=context(req);self.req=req;self.cp=None;self.valid=True;self.writes=[]
    async def validate_current_execution(self):
        if not self.valid:raise PermissionError('revoked')
    async def load_checkpoint(self,*args):return {'checkpoint':copy.deepcopy(self.cp)}
    async def save_checkpoint(self,ns,key,schema,value,expected,operation):
        assert expected==(0 if self.cp is None else self.cp['revision'])
        self.cp={'revision':expected+1,'schema_id':schema,'value':copy.deepcopy(value),'content_hash':'d'*64,
            'execution_revision':json.loads(ExecutionLifecycle._identity(self.req).key)[1],
            'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
        self.writes.append(operation);return {'checkpoint':copy.deepcopy(self.cp)}
    async def load_recovery_checkpoint(self,ref):return {'state_key':ref['state_key'],'checkpoint':copy.deepcopy(self.cp)}

class Graph:
    def __init__(self,req):self.snapshot=SimpleNamespace(config={'configurable':{'checkpoint_id':''}},values={},next=(),tasks=());self.req=req;self.calls=[];self.history=[]
    async def aget_state(self,config):return self.snapshot
    async def aget_state_history(self,config,limit=64):
        for row in self.history[:limit]:yield row
    async def ainvoke(self,value,config):self.calls.append(value);self.complete();return copy.deepcopy(self.snapshot.values)
    def complete(self):
        self.history.insert(0,self.snapshot)
        self.snapshot=SimpleNamespace(config={'configurable':{'checkpoint_id':'cp-done'}},
          values={'context':vars(context(self.req)),'answer':{'facts_supported':True}},next=(),tasks=())

def recovery(original,client):
    req=request(5,'b');req.operation='resume';cp=client.cp
    ref={key:cp[key] for key in ['revision','schema_id','content_hash','execution_revision','expires_at']}
    ref['state_key']=checkpoint_state_key(req.scope,NAMESPACE,KEY)
    req.resume_input={'version':'runtime-recovery/v1','origin_operation':'invoke','reference':{
        'version':'runtime-recovery-stop/v1','run_id':req.scope.run_id,'stopped_revision':2,'ready_revision':4,
        'operation':'invoke','body_hash':'c'*64,'policy_hash':'c'*64,'lease_token_hash':'a'*64,
        'request_hash':'c'*64,'resume_input_hash':'c'*64,'source':'sdk-cancel-exit/v1','checkpoints':[ref]}}
    client.req=req;client._context=context(req);return req

CONFIG={'configurable':{'thread_id':'scope-v2:fixture'}}

@pytest.mark.asyncio
async def test_normal_dispatch_publishes_reference_only_and_reads_completed_graph_on_recovery():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge();work_calls=[]
    async def work():work_calls.append(1);graph.complete();return copy.deepcopy(graph.snapshot.values)
    first=await bridge.execute(req,client,graph,CONFIG,work)
    assert len(client.writes)==2 and client.cp['value']['phase']=='completed'
    assert 'platform_context_token' not in json.dumps(client.cp)
    restored=recovery(req,client)
    second=await bridge.execute(restored,client,graph,CONFIG,work)
    assert first==second and work_calls==[1] and graph.calls==[]

@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['scope','input','checkpoint','missing','expired','revoked'])
async def test_foreign_changed_missing_expired_and_revoked_recovery_never_executes(failure):
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def work():graph.complete();return graph.snapshot.values
    await bridge.execute(req,client,graph,CONFIG,work);restored=recovery(req,client)
    if failure=='scope':graph.snapshot.values['context']['actor_id']='foreign'
    elif failure=='input':restored.input['extra']='changed'
    elif failure=='checkpoint':graph.snapshot.config['configurable']['checkpoint_id']='foreign-cp'
    elif failure=='missing':client.cp=None
    elif failure=='expired':restored.resume_input['reference']['checkpoints'][0]['expires_at']='2000-01-01T00:00:00Z'
    elif failure=='revoked':client.valid=False
    with pytest.raises((DomainExecutionError,PermissionError,TypeError)):
        await bridge.execute(restored,client,graph,CONFIG,work)
    assert graph.calls==[]

@pytest.mark.asyncio
async def test_uncompleted_checkpoint_continues_only_pending_graph_nodes():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def work():graph.complete();return graph.snapshot.values
    await bridge.execute(req,client,graph,CONFIG,work)
    graph.snapshot.next=('pending-node',)
    client.cp['value']['phase']='dispatch'
    restored=recovery(req,client)
    result=await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('must not invoke original work'))
    assert graph.calls==[None] and result['answer']['facts_supported']

@pytest.mark.asyncio
async def test_waiting_business_review_needs_committed_review_and_no_self_approval():
    req=request();req.operation='resume';req.resume_input={'decision':'approve','reviewer_id':req.scope.principal_id}
    client=Client(req);graph=Graph(req)
    with pytest.raises(DomainExecutionError):
        await PublicGraphCheckpointBridge().execute(req,client,graph,CONFIG,lambda:pytest.fail('self-review ran'))
    assert client.writes==[] and graph.calls==[]

@pytest.mark.asyncio
async def test_committed_platform_review_recovers_waiting_graph_before_agent_received_review():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    interrupt=SimpleNamespace(value={'review':'required'})
    async def work():
        graph.complete();graph.snapshot.next=('review-node',)
        graph.snapshot.tasks=(SimpleNamespace(interrupts=(interrupt,)),)
        return {**graph.snapshot.values,'__interrupt__':(interrupt,)}
    await bridge.execute(req,client,graph,CONFIG,work)
    assert client.cp['value']['phase']=='waiting' and client.cp['value']['business_resume']=={}
    restored=recovery(req,client)
    restored.resume_input['reference']['operation']='resume'
    restored.resume_input['business_review']={'decision':'approve','reviewer_id':'assigned-reviewer'}
    result=await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('original work replayed'))
    assert result['answer']['facts_supported'] and len(graph.calls)==1
    assert graph.calls[0].resume=={'decision':'approve','reviewer_id':'assigned-reviewer'}
    assert client.cp['value']['phase']=='completed'

@pytest.mark.asyncio
@pytest.mark.parametrize('bad',['self','extra','null','token','group','invoke','invalid_id','conflict'])
async def test_unbound_review_never_releases_interrupted_graph(bad):
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def work():
        graph.complete();graph.snapshot.next=('review-node',)
        graph.snapshot.tasks=(SimpleNamespace(interrupts=(SimpleNamespace(value={}),)),)
        return {**graph.snapshot.values,'__interrupt__':(True,)}
    await bridge.execute(req,client,graph,CONFIG,work)
    restored=recovery(req,client);marker=restored.resume_input
    marker['reference']['operation']='resume'
    marker['business_review']={'decision':'approve','reviewer_id':'assigned-reviewer'}
    if bad=='self':marker['business_review']['reviewer_id']=restored.scope.principal_id
    elif bad=='extra':marker['business_review']['confirmation_token']='untrusted'
    elif bad=='null':marker['business_review']=None
    elif bad=='token':marker['confirmation_token']='untrusted'
    elif bad=='group':marker['group_resume']={}
    elif bad=='invoke':marker['reference']['operation']='invoke'
    elif bad=='invalid_id':marker['business_review']['reviewer_id']='with space'
    elif bad=='conflict':client.cp['value']['business_resume']={'decision':'reject','reviewer_id':'assigned-reviewer'}
    with pytest.raises(DomainExecutionError):
        await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('original work replayed'))
    assert graph.calls==[]

@pytest.mark.asyncio
async def test_request_changes_waits_and_a_new_reviewer_decision_can_finish():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def initial():
        graph.complete();graph.snapshot.next=('review-node',)
        graph.snapshot.tasks=(SimpleNamespace(interrupts=(SimpleNamespace(value={}),)),)
        return {**graph.snapshot.values,'__interrupt__':(True,)}
    await bridge.execute(req,client,graph,CONFIG,initial)
    req=request(3,'b');req.operation='resume';req.resume_input={'decision':'request_changes','reviewer_id':'assigned-reviewer','comment':'Please supply the effective date.'}
    client.req=req;client._context=context(req)
    async def material():return await initial()
    result=await bridge.execute(req,client,graph,CONFIG,material)
    assert result['__interrupt__'] and client.cp['value']['phase']=='waiting'
    assert client.cp['value']['business_resume']==req.resume_input
    req=request(4,'c');req.operation='resume';req.resume_input={'decision':'reject','reviewer_id':'assigned-reviewer','comment':'Teaching case ended.'}
    client.req=req;client._context=context(req)
    async def finish():graph.complete();return graph.snapshot.values
    await bridge.execute(req,client,graph,CONFIG,finish)
    assert client.cp['value']['phase']=='completed' and client.cp['value']['business_resume']['decision']=='reject'

@pytest.mark.asyncio
async def test_committed_material_request_survives_runtime_recovery():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def initial():
        graph.complete();graph.snapshot.next=('review-node',)
        graph.snapshot.tasks=(SimpleNamespace(interrupts=(SimpleNamespace(value={}),)),)
        return {**graph.snapshot.values,'__interrupt__':(True,)}
    await bridge.execute(req,client,graph,CONFIG,initial)
    restored=recovery(req,client);restored.resume_input['reference']['operation']='resume'
    restored.resume_input['business_review']={'decision':'request_changes','reviewer_id':'assigned-reviewer'}
    await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('original work replayed'))
    assert graph.calls[0].resume==restored.resume_input['business_review']

@pytest.mark.asyncio
async def test_new_committed_decision_recovers_a_previous_material_wait():
    req=request();client=Client(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def initial():
        graph.complete();graph.snapshot.next=('review-node',)
        graph.snapshot.tasks=(SimpleNamespace(interrupts=(SimpleNamespace(value={}),)),)
        return {**graph.snapshot.values,'__interrupt__':(True,)}
    await bridge.execute(req,client,graph,CONFIG,initial)
    client.cp['value']['business_resume']={'decision':'request_changes','reviewer_id':'assigned-reviewer','comment':'Supply a date.'}
    restored=recovery(req,client);restored.resume_input['reference']['operation']='resume'
    restored.resume_input['business_review']={'decision':'reject','reviewer_id':'assigned-reviewer'}
    await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('original work replayed'))
    assert graph.calls[0].resume['decision']=='reject'


class PublishedCapacityClient(Client):
    def __init__(self,req,limit=4096):
        super().__init__(req);self.limit=limit
    def metadata(self,result):
        return {**result,'checkpoint_history':{'version':'checkpoint-history/v1','max_revisions':self.limit}}
    async def load_checkpoint(self,*args):
        return self.metadata(await super().load_checkpoint(*args))
    async def load_recovery_checkpoint(self,ref):
        return self.metadata(await super().load_recovery_checkpoint(ref))


@pytest.mark.asyncio
@pytest.mark.parametrize('revision',[64,2000,4094])
async def test_published_capacity_allows_high_graph_marker_and_exact_recovery(revision):
    req=request();client=PublishedCapacityClient(req);graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def work():graph.complete();return graph.snapshot.values
    await bridge.execute(req,client,graph,CONFIG,work)
    client.cp['revision']=revision
    client.cp['value']['phase']='dispatch';graph.snapshot.next=('pending-node',)
    restored=recovery(req,client)
    result=await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('no original work replay'))
    assert result['answer']['facts_supported'] and graph.calls==[None]
    assert client.cp['revision']==revision+2


@pytest.mark.asyncio
@pytest.mark.parametrize('limit,revision',[(None,63),(64,63),(4096,4095),(1,0)])
async def test_insufficient_marker_capacity_denies_before_work_or_state_write(limit,revision):
    req=request();client=Client(req) if limit is None else PublishedCapacityClient(req,limit)
    graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    if revision:
        async def initial():graph.complete();return graph.snapshot.values
        await bridge.execute(req,client,graph,CONFIG,initial)
        client.cp['revision']=revision
    before=len(client.writes)
    with pytest.raises(DomainExecutionError):
        await bridge.execute(req,client,graph,CONFIG,lambda:pytest.fail('capacity admission must precede work'))
    assert len(client.writes)==before and graph.calls==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('published,found',[(True,True),(True,False),(False,False)])
async def test_crash_anchor_search_uses_published_bounded_history(published,found):
    req=request();client=PublishedCapacityClient(req) if published else Client(req)
    graph=Graph(req);bridge=PublicGraphCheckpointBridge()
    async def work():graph.complete();return graph.snapshot.values
    await bridge.execute(req,client,graph,CONFIG,work)
    client.cp['value'].update(phase='dispatch',checkpoint_id='anchor')
    graph.snapshot.next=('pending-node',)
    # A no-approval cursor can execute >64 nodes between entry and exit.
    graph.history=[SimpleNamespace(config={'configurable':{'checkpoint_id':f'cp-{i}'}}) for i in range(2000)]
    graph.history[-1].config['configurable']['checkpoint_id']='anchor' if found or not published else 'other'
    expected=4096 if published else 64
    limits=[];closed=[]
    async def history(config,limit):
        limits.append(limit)
        try:
            for row in graph.history[:limit]:yield row
        finally:closed.append(True)
    graph.aget_state_history=history
    restored=recovery(req,client)
    if found:
        await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('original replay'))
        assert graph.calls==[None]
    else:
        with pytest.raises(DomainExecutionError):
            await bridge.execute(restored,client,graph,CONFIG,lambda:pytest.fail('unproven anchor'))
        assert graph.calls==[]
    assert limits==[expected]
    assert closed==[True]

@pytest.mark.parametrize('review',[{'decision':'request_changes','reviewer_id':'with space'}, {'decision':'request_changes','reviewer_id':'reviewer','comment':3}, {'decision':'request_changes','reviewer_id':'reviewer','comment':'x'*2001}, {'decision':'request_changes','reviewer_id':'reviewer','confirmation_token':'untrusted'}])
def test_material_review_still_rejects_malformed_or_authority_fields(review):
    with pytest.raises(DomainExecutionError):business_review(review)
