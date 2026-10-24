"""Published public-State capacity; no providers or business gold used."""
import copy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.checkpoint_capacity import context_key, remember, reply_limit, revision_limit
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.models import RecoveryCheckpointReference
from agent_platform_sdk.recovery_context import _metadata

SCHEMA = "schema://fixture/graph/v1"
HISTORY = {"version": "checkpoint-history/v1", "max_revisions": 4096}


class Client(CapabilityGatewayClient):
    def __init__(self):
        fields = ("tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id",
                  "agent_id", "agent_version_id", "principal_type", "actor_id", "session_id", "task_id", "memory_policy_id")
        self._context = SimpleNamespace(**{name: "fixture-"+name for name in fields}, authorization_epoch=1)
        self.posts = []
        self.metadata = True
        self.cp = None

    async def _post(self, path, payload, timeout):
        self.posts.append(copy.deepcopy(payload))
        if payload["operation"] == "save":
            self.cp = {"revision": payload["expected_revision"]+1, "schema_id": SCHEMA,
                       "value": payload["value"], "execution_revision": 2, "content_hash": "b"*64,
                       "expires_at": (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()}
        result = {"state_key": "a"*64, "checkpoint": copy.deepcopy(self.cp)}
        if self.metadata:
            result["checkpoint_history"] = copy.deepcopy(HISTORY)
        return result


@pytest.mark.asyncio
async def test_negotiated_capacity_crosses_64_and_verifies_recovery_without_resend():
    client = Client()
    with pytest.raises(ValueError):
        await client.save_checkpoint("graph", "main", SCHEMA, {}, 64, "unnegotiated")
    assert client.posts == []
    await client.load_checkpoint("graph", "main", SCHEMA)
    saved = await client.save_checkpoint("graph", "main", SCHEMA, {"confirmed": True}, 4001, "once")
    assert saved["checkpoint"]["revision"] == 4002
    ref = {"state_key": saved["state_key"], **{k:v for k,v in saved["checkpoint"].items() if k!="value"}}
    # This exported model is the specialised Agent-group handoff reference.
    RecoveryCheckpointReference.model_validate({**ref, "schema_id": "schema://agentplug/agent-group/v1"})
    client._checkpoint_history_limits.clear()  # process restart learns via captured reference read
    restored = await client.load_recovery_checkpoint(ref)
    ExecutionLifecycle._verify_recovery_checkpoint_response(ref, restored)
    assert _metadata(restored, ref["state_key"], SCHEMA)["checkpoint"]["revision"] == 4002
    assert revision_limit(client) == 4096
    assert sum(p["operation"] == "save" for p in client.posts) == 1
    with pytest.raises(ValueError):
        await client.save_checkpoint("graph", "main", SCHEMA, {}, 4096, "overflow")


@pytest.mark.parametrize("field", ["tenant_id", "department_id", "application_id", "installation_id", "agent_instance_id",
                                  "agent_id", "agent_version_id", "principal_type", "actor_id", "session_id", "task_id", "memory_policy_id", "authorization_epoch"])
def test_negotiated_capacity_never_crosses_scope_policy_or_epoch(field):
    client = Client()
    remember(client, {"checkpoint_history": HISTORY})
    assert revision_limit(client) == 4096
    setattr(client._context, field, 2 if field == "authorization_epoch" else "another")
    assert revision_limit(client) == 64


@pytest.mark.parametrize("metadata", [None, {}, {**HISTORY,"max_revisions":True}, {**HISTORY,"max_revisions":0},
                                       {**HISTORY,"max_revisions":4097}, {**HISTORY,"max_revisions":1.5},
                                       {**HISTORY,"version":"unknown"}, {**HISTORY,"other":1}])
def test_malformed_capacity_never_grants_larger_history(metadata):
    client = Client()
    with pytest.raises(GatewayError):
        remember(client, {"checkpoint_history":metadata})
    assert revision_limit(client) == 64


def test_legacy_reply_restores_default_and_cache_stays_bounded():
    client = Client()
    for index in range(40):
        client._context.task_id = str(index)
        remember(client, {"checkpoint_history":HISTORY})
    assert len(client._checkpoint_history_limits) == 32
    remember(client, {"state_key":"a"*64,"checkpoint":None})
    assert revision_limit(client) == 64
    assert reply_limit({}) == 64
    assert context_key(SimpleNamespace()) is None
