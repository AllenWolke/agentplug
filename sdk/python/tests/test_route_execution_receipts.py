import copy
from pathlib import Path
import time

import pytest

from agent_platform_sdk.durable_stage import DurableStageClient
from agent_platform_sdk.harness import _budget_output, _limit_output
from agent_platform_sdk.capability_client import GatewayError
from test_public_harness import Fixture


def retained_receipt():
    return {'version':'model-route-execution-receipt/v1','status':'completed','attempts':2,
        'retained_unknown_attempts':1,'retained_reservation_micros':120,'execution_sha256':'a'*64}


@pytest.mark.asyncio
async def test_durable_stage_preserves_retained_original_accounting():
    class Client:
        async def run_harness(self,*args,**kwargs):
            return {'status':'completed','output':{'text':'alternate answer','model':'alternate',
                'usage':{'input_tokens':3,'output_tokens':2},'route_execution':retained_receipt()},'execution':{}}
    stage=DurableStageClient(Client(),key='question',deadline_ms=int(time.time()*1000)+30000)
    response=await stage.chat([{'role':'user','content':'question'}])
    assert response['route_execution']==retained_receipt()


@pytest.mark.parametrize('project',[lambda r:_budget_output(r,'budget_exhausted'),lambda r:_limit_output(r,'rounds')])
def test_harness_limits_preserve_accounting_disposition_without_aliasing(project):
    original={'route_execution':retained_receipt()}
    expected=copy.deepcopy(original)
    output=project(original)
    assert output['route_execution']==expected['route_execution']
    output['route_execution']['retained_unknown_attempts']=0
    assert original==expected


def test_sdk_receipt_projection_templates_are_identical():
    root=Path(__file__).resolve().parents[3]
    for filename in ('harness.py','durable_stage.py'):
        actual=(root/'sdk/python/agent_platform_sdk'/filename).read_bytes()
        for name in ('python-generic','python-langgraph'):
            assert (root/'templates'/name/'platform_entry/agent_platform_sdk'/filename).read_bytes()==actual


@pytest.mark.asyncio
@pytest.mark.parametrize('supported',[False,True])
async def test_parent_deadline_is_negotiated_persisted_and_not_reset(supported):
    class Client(Fixture):
        def __init__(self):
            super().__init__()
            self.commands=[]

        async def prepare_context(self,*args,**kwargs):
            prepared=await super().prepare_context(*args,**kwargs)
            if supported:prepared['model_route_execution']='model-route-execution/v1'
            return prepared

        async def _post(self,path,command,timeout):
            if path.endswith('model/generate'):
                self.commands.append(copy.deepcopy(command))
                return {'text':'completed alternate answer','completion_status':'complete','route_execution':retained_receipt()}
            return await super()._post(path,command,timeout)
    client=Client()
    deadline=int(time.time()*1000)+25000
    request={'messages':[{'role':'user','content':'question'}],'function_names':[],'idempotency_key':'parent-call','deadline_ms':deadline+100000}
    await client.run_harness(request,key='loop',max_rounds=1,max_tool_calls=1,extension_id='deadline-test/v1',deadline_ms=deadline)
    assert len(client.commands)==1
    if supported:assert client.commands[0]['deadline_ms']==deadline
    else:assert 'deadline_ms' not in client.commands[0]
    await client.run_harness(request,key='loop',max_rounds=1,max_tool_calls=1,extension_id='deadline-test/v1',deadline_ms=deadline)
    with pytest.raises(GatewayError,match='HARNESS_STATE_REJECTED'):
        await client.run_harness(request,key='loop',max_rounds=1,max_tool_calls=1,extension_id='deadline-test/v1',deadline_ms=deadline+30000)
    assert len(client.commands)==1
    assert client.checkpoint['value']['loop_deadline_ms']==deadline
