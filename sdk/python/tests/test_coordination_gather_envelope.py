"""The runner consumes the public gather envelope, preserving live disclosure."""
import copy
from types import SimpleNamespace

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.coordination import STATE_SCHEMA, agent_group_plan_input_hash, run_agent_group
from agent_platform_sdk.execution_lifecycle import AgentGroupPause

class GatherPort:
    def __init__(self, terminal, status, outputs_complete):
        self._context = SimpleNamespace(task_id='parent', input_fingerprint='a' * 64)
        self.inputs = [{'service': 'teaching'}]
        self.calls = []
        self.value = {
            'version': 'agent-group/v1', 'group_key': 'group', 'operation_key': 'diagnosis',
            'parent_run_id': 'parent', 'input_hash': agent_group_plan_input_hash('diagnosis', 'operations.diagnosis', self.inputs),
            'input_fingerprint': 'a' * 64, 'phase': 'gather', 'ordinal': 1,
            'targets': [{'output_schema': 'schema://operations/output/v2'}],
            'bindings': [{'child_key': 'b' * 64, 'input_fingerprint': 'c' * 64,
                          'output_schema': 'schema://operations/output/v2'}],
            'child_keys': ['b' * 64],
        }
        self.receipt = {'group': {'terminal': terminal, 'status': status,
                                 'outputs_complete': outputs_complete,
                                 'children': [{'child_key': 'b' * 64}]}}
    def _current_group_resume_binding(self):
        return None
    async def load_checkpoint(self, *args, **kwargs):
        self.calls.append('load')
        return {'state_key': 'd' * 64, 'checkpoint': {'revision': 1, 'schema_id': STATE_SCHEMA,
                'value': copy.deepcopy(self.value), 'content_hash': 'e' * 64,
                'execution_revision': 3, 'expires_at': '2030-01-01T00:00:00Z'}}
    async def gather_agent_children(self, *args, **kwargs):
        self.calls.append('gather')
        return copy.deepcopy(self.receipt)

@pytest.mark.asyncio
async def test_current_nonterminal_envelope_parks_exact_durable_group_without_admitting_again():
    port = GatherPort(False, 'in_progress', False)
    with pytest.raises(AgentGroupPause) as paused:
        await run_agent_group(port, port.inputs, key='group', operation_key='diagnosis', task_type='operations.diagnosis')
    assert paused.value.child_keys == ('b' * 64,)
    assert paused.value.checkpoint.revision == 1
    assert port.calls == ['load', 'gather', 'load']

@pytest.mark.asyncio
async def test_terminal_success_keeps_public_envelope_and_returns_only_current_gather():
    port = GatherPort(True, 'completed', True)
    actual = await run_agent_group(port, port.inputs, key='group', operation_key='diagnosis', task_type='operations.diagnosis')
    assert actual == port.receipt
    assert port.calls == ['load', 'gather']

@pytest.mark.asyncio
async def test_failed_terminal_group_cannot_be_disclosed_as_success_or_retried():
    port = GatherPort(True, 'failed', False)
    with pytest.raises(GatewayError) as denied:
        await run_agent_group(port, port.inputs, key='group', operation_key='diagnosis', task_type='operations.diagnosis')
    assert denied.value.code == 'AGENT_GROUP_REJECTED'
    assert port.calls == ['load', 'gather']
