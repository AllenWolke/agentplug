import asyncio
import copy
import json
from types import SimpleNamespace
import httpx
import pytest
from agent_platform_sdk.capability_client import CapabilityGatewayClient,GatewayError

class Context(SimpleNamespace):
 def model_dump(self):return vars(self)

@pytest.fixture(autouse=True)
def security(monkeypatch):
 monkeypatch.setenv('APP_ENV','test');monkeypatch.setenv('INTERNAL_SIGNING_SECRET','synthetic-response-loss-fixture-only')

def result():
 return {'data':{'fact':'independently-committed'},'observation':{'version':'runtime-observation/v1','tool_name':'read.evidence','call_id':'original-call','status':'succeeded','effect':'completed','instruction_trust':'untrusted_data','context_output':{'fact':'independently-committed'}}}

def receipt():
 return {'version':'tool-receipt/v1','status':'completed','tool_name':'read.evidence','call_id':'original-call','receipt':result()}

def client(handler):
 return CapabilityGatewayClient(Context(task_id='trusted-fixture-run',actor_id='fixture',platform_context_token='synthetic-context',trace_id='fixture'),base_url='http://fixture.invalid',token='synthetic-internal',transport=httpx.MockTransport(handler))

@pytest.mark.asyncio
@pytest.mark.parametrize('error_type',[httpx.RemoteProtocolError,httpx.ReadError,httpx.WriteError,httpx.ConnectError,httpx.ReadTimeout])
async def test_transport_loss_reads_original_receipt_once_and_never_reinvokes(error_type):
 calls=[]
 async def handler(request):
  data=json.loads(request.content)['input'];calls.append((request.url.path,data))
  if len(calls)==1:raise error_type('synthetic transport failure',request=request)
  assert request.url.path=='/internal/tool/receipt'
  return httpx.Response(200,json={'data':receipt()})
 assert await client(handler).invoke_tool('read.evidence',{'batch':'fixture'},call_id='original-call',confirmed=True,confirmation_token='approved-operation-token',timeout=1)==result()
 assert [p for p,_ in calls]==['/internal/tool/invoke','/internal/tool/receipt']
 assert calls[1][1]=={'name':'read.evidence','payload':{'batch':'fixture'},'call_id':'original-call','confirmation_token':'approved-operation-token'}

@pytest.mark.asyncio
@pytest.mark.parametrize('changed,expected',[
 (('version','wrong'),'TOOL_RECEIPT_REJECTED'),(('tool_name','other'),'TOOL_RECEIPT_REJECTED'),(('call_id','other'),'TOOL_RECEIPT_REJECTED'),
 (('status','running'),'TOOL_RESULT_UNKNOWN'),(('status','not_found'),'TOOL_RESULT_UNKNOWN'),(('status','unknown'),'TOOL_RESULT_UNKNOWN'),
 (('receipt',None),'TOOL_RECEIPT_REJECTED')])
async def test_unbound_or_incomplete_receipt_never_fakes_success_or_resends(changed,expected):
 calls=[];value=receipt();value[changed[0]]=changed[1]
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.ReadError('lost',request=request)
  return httpx.Response(200,json={'data':value})
 with pytest.raises(GatewayError) as error:await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert error.value.code==expected and calls==['/internal/tool/invoke','/internal/tool/receipt']

@pytest.mark.asyncio
@pytest.mark.parametrize('field,value',[('tool_name','other'),('call_id','other'),('effect','unknown'),('status','failed'),('instruction_trust','trusted')])
async def test_nested_observation_binding_is_checked(field,value):
 r=receipt();r['receipt']['observation'][field]=value;calls=[]
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.RemoteProtocolError('lost',request=request)
  return httpx.Response(200,json={'data':r})
 with pytest.raises(GatewayError,match='TOOL_RECEIPT_REJECTED'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert len(calls)==2

@pytest.mark.asyncio
@pytest.mark.parametrize('payload',[[1,2],'native string',None])
async def test_generic_tool_data_is_not_reinterpreted(payload):
 r=receipt();r['receipt']['data']=payload;calls=[]
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.ReadError('lost',request=request)
  return httpx.Response(200,json={'data':r})
 actual=await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert actual['data']==payload and len(calls)==2

@pytest.mark.asyncio
async def test_authority_denial_at_receipt_is_not_hidden_or_retried():
 calls=[]
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.ReadError('lost',request=request)
  return httpx.Response(403,json={'code':'CAPABILITY_DENIED','message':'current permission revoked'})
 with pytest.raises(GatewayError,match='CAPABILITY_DENIED'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert len(calls)==2

@pytest.mark.asyncio
async def test_known_tool_denial_does_not_query_receipt():
 calls=[]
 async def handler(request):
  calls.append(request.url.path);return httpx.Response(403,json={'code':'CAPABILITY_DENIED','message':'denied'})
 with pytest.raises(GatewayError,match='CAPABILITY_DENIED'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert calls==['/internal/tool/invoke']

@pytest.mark.asyncio
async def test_normal_success_keeps_one_http_call():
 calls=[]
 async def handler(request):calls.append(request.url.path);return httpx.Response(200,json={'data':result()})
 assert await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)==result()
 assert calls==['/internal/tool/invoke']

@pytest.mark.asyncio
async def test_expired_original_budget_does_not_grant_a_new_receipt_window():
 calls=[]
 async def handler(request):
  calls.append(request.url.path);await asyncio.sleep(.02);raise httpx.ReadError('lost',request=request)
 with pytest.raises(GatewayError,match='TOOL_RESULT_UNKNOWN'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=.005)
 assert calls==['/internal/tool/invoke']

@pytest.mark.asyncio
@pytest.mark.parametrize('cause',['timeout','network'])
async def test_receipt_unavailability_is_bounded_without_another_invoke(cause):
 calls=[];started=asyncio.get_running_loop().time()
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.ReadError('lost',request=request)
  if cause=='timeout':await asyncio.sleep(10)
  raise httpx.ReadError('receipt unavailable',request=request)
 with pytest.raises(GatewayError,match='TOOL_RESULT_UNKNOWN'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=.02)
 assert len(calls)==2 and asyncio.get_running_loop().time()-started<.5

@pytest.mark.asyncio
@pytest.mark.parametrize('at',['invoke','receipt'])
async def test_cancellation_propagates_without_another_operation(at):
 calls=[]
 async def handler(request):
  calls.append(request.url.path)
  if at=='receipt' and len(calls)==1:raise httpx.ReadError('lost',request=request)
  raise asyncio.CancelledError()
 with pytest.raises(asyncio.CancelledError):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert len(calls)==(1 if at=='invoke' else 2)

@pytest.mark.asyncio
async def test_model_transport_loss_never_uses_tool_receipt_or_repeats_model():
 calls=[]
 async def handler(request):calls.append(request.url.path);raise httpx.ReadError('lost model response',request=request)
 with pytest.raises(httpx.ReadError):await client(handler)._post('/internal/model/generate',{'idempotency_key':'model-original'},1)
 assert calls==['/internal/model/generate']

@pytest.mark.asyncio
@pytest.mark.parametrize('code,expected',[
 ('TOOL_INVOCATION_IN_PROGRESS','TOOL_RESULT_UNKNOWN'),
 ('TOOL_CONFIRMATION_REQUIRED','CAPABILITY_DENIED'),
 ('MODEL_BUDGET_EXCEEDED','CAPABILITY_DENIED'),
 ('RUN_LEASE_LOST','RUN_LEASE_LOST'),
 ('AUTHORIZATION_REVOKED','AUTHORIZATION_REVOKED')])
async def test_receipt_errors_cannot_reenter_invoke_approval_or_budget_branches(code,expected):
 calls=[]
 async def handler(request):
  calls.append(request.url.path)
  if len(calls)==1:raise httpx.ReadError('lost',request=request)
  return httpx.Response(409,json={'code':code,'message':'synthetic receipt refusal'})
 with pytest.raises(GatewayError) as error:await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=1)
 assert error.value.code==expected and calls==['/internal/tool/invoke','/internal/tool/receipt']

@pytest.mark.asyncio
async def test_unbounded_legacy_timeout_does_not_create_an_unbounded_recovery():
 calls=[]
 async def handler(request):calls.append(request.url.path);raise httpx.ReadError('lost',request=request)
 with pytest.raises(GatewayError,match='TOOL_RESULT_UNKNOWN'):await client(handler).invoke_tool('read.evidence',{},call_id='original-call',timeout=None)
 assert calls==['/internal/tool/invoke']

@pytest.mark.asyncio
async def test_normal_model_call_keeps_legacy_none_timeout():
 calls=[]
 async def handler(request):calls.append(request.url.path);return httpx.Response(200,json={'data':{'text':'known'}})
 assert await client(handler)._post('/internal/model/generate',{'idempotency_key':'model-original'},None)=={'text':'known'}
 assert calls==['/internal/model/generate']

@pytest.mark.asyncio
async def test_committed_tool_response_loss_reads_original_receipt_without_second_invoke(monkeypatch):
    monkeypatch.setenv('APP_ENV','test')
    monkeypatch.setenv('INTERNAL_SIGNING_SECRET','synthetic-response-loss-fixture-only')
    requests=[];effects=0
    result={'data':{'fact':'independent-mapping-snapshot'},'observation':{'version':'runtime-observation/v1',
        'tool_name':'get_mapping_evidence','call_id':'original-call','status':'succeeded','effect':'completed',
        'instruction_trust':'untrusted_data','context_output':{'fact':'independent-mapping-snapshot'}}}
    async def handler(request):
        nonlocal effects
        body=json.loads(request.content);requests.append((request.url.path,body['input']))
        if request.url.path=='/internal/tool/invoke':
            effects+=1
            raise httpx.RemoteProtocolError('response lost after durable receipt',request=request)
        assert request.url.path=='/internal/tool/receipt'
        return httpx.Response(200,json={'data':{'version':'tool-receipt/v1','status':'completed','tool_name':'get_mapping_evidence','call_id':'original-call','receipt':result}})
    client=CapabilityGatewayClient(Context(task_id='trusted-fixture-run',actor_id='fixture',platform_context_token='synthetic-context',trace_id='fixture'),
        base_url='http://fixture.invalid',token='synthetic-internal',transport=httpx.MockTransport(handler))
    actual=await client.invoke_tool('get_mapping_evidence',{'batch_id':'synthetic'},call_id='original-call',timeout=1)
    assert actual==result
    assert effects==1
    assert [p for p,_ in requests]==['/internal/tool/invoke','/internal/tool/receipt']
    assert requests[1][1]=={'name':'get_mapping_evidence','call_id':'original-call','payload':{'batch_id':'synthetic'}}
