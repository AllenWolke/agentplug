import asyncio,base64,copy,hashlib,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace
import pytest
from agent_platform_sdk.models import ExecuteRequest
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.graph_recovery import PublicGraphCheckpointBridge,SCHEMA,NAMESPACE,KEY
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
