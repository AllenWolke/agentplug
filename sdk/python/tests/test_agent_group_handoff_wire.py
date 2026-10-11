"""The supervised Python child-group receipt must serialize and reject tampering."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_platform_sdk.models import AgentGroupHandoff, ExecuteResponse


def handoff_payload():
    return {
        'version': 'sdk-agent-group-exit/v1', 'run_id': 'parent-run',
        'execution_revision': 3, 'body_hash': 'a' * 64, 'lease_token_hash': 'b' * 64,
        'input_fingerprint': 'c' * 64, 'origin_operation': 'run',
        'group_key': 'document-collaboration', 'operation_key': 'diagnosis',
        'last_event_seq': 8,
        'checkpoint': {
            'state_key': 'd' * 64, 'revision': 1,
            'schema_id': 'schema://agentplug/agent-group/v1', 'content_hash': 'e' * 64,
            'execution_revision': 3,
            'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        },
        'child_keys': ['f' * 64],
    }


def test_waiting_response_round_trips_supervised_child_group_receipt():
    payload = handoff_payload()
    response = ExecuteResponse(run_id='parent-run', status='waiting',
                               agent_group_handoff=AgentGroupHandoff.model_validate(payload))
    restored = ExecuteResponse.model_validate_json(response.model_dump_json())
    assert restored.agent_group_handoff is not None
    assert restored.agent_group_handoff.model_dump() == payload


@pytest.mark.parametrize('keys', [[], ['f' * 64, 'f' * 64], ['F' * 64], ['f' * 63], ['*']])
def test_handoff_rejects_invalid_or_duplicate_child_identity(keys):
    payload = handoff_payload()
    payload['child_keys'] = keys
    with pytest.raises(ValidationError):
        AgentGroupHandoff.model_validate(payload)
