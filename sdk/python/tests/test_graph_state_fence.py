import copy
from datetime import datetime, timedelta, timezone
import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient, GatewayError
from agent_platform_sdk.errors import DomainExecutionError
from agent_platform_sdk.graph_state_fence import bind, close
from agent_platform_sdk.recovery_context import checkpoint_state_key
from test_graph_recovery import request, context

SCHEMA = "schema://agentplug/step-workflow/v1"


class Client(CapabilityGatewayClient):
    def __init__(self, req):
        self._context = context(req)
        self.key = checkpoint_state_key(req.scope, "step-workflow", "dynamic")
        self.cp = {"revision": 1, "schema_id": SCHEMA, "content_hash": "a" * 64,
                   "execution_revision": 2, "value": {"phase": "dispatch"},
                   "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}
        self.paths = []

    async def _post(self, path, payload, timeout):
        self.paths.append(copy.deepcopy(payload))
        if payload["operation"] == "save":
            self.cp.update(revision=self.cp["revision"] + 1 if self.cp else 1,
                           schema_id=payload["schema_id"], value=copy.deepcopy(payload["value"]))
        return {"state_key": self.key, "checkpoint": copy.deepcopy(self.cp)}

    def reference(self):
        return {"state_key": self.key, **{key: value for key, value in self.cp.items() if key != "value"}}


@pytest.mark.asyncio
async def test_dynamic_child_uses_exact_reference_then_tracks_new_cas_head():
    req = request()
    client = Client(req)
    fence, token = bind(req.scope, [client.reference()])
    try:
        await client.load_checkpoint("step-workflow", "dynamic", SCHEMA)
        assert "reference" in client.paths[0] and "namespace" not in client.paths[0]
        await client.save_checkpoint("step-workflow", "dynamic", SCHEMA, {"phase": "completed"}, 1, "complete")
        result = await client.load_checkpoint("step-workflow", "dynamic", SCHEMA)
        assert result["checkpoint"]["revision"] == client.paths[-1]["reference"]["revision"] == 2
    finally:
        close(fence, token)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["uncaptured", "stale", "expired", "schema", "historical", "save_without_head", "detached"])
async def test_dynamic_child_invalid_head_never_authorizes_a_write(failure):
    req = request()
    client = Client(req)
    reference = client.reference()
    if failure == "expired":
        reference["expires_at"] = client.cp["expires_at"] = "2000-01-01T00:00:00Z"
    fence, token = bind(req.scope, [] if failure in {"uncaptured", "save_without_head"} else [reference])
    try:
        if failure == "stale":
            client.cp["revision"] += 1
        if failure == "detached":
            fence.active = False
        with pytest.raises((GatewayError, DomainExecutionError)):
            if failure == "save_without_head":
                await client.save_checkpoint("step-workflow", "dynamic", SCHEMA, {}, 0, "invalid")
            else:
                await client.load_checkpoint("step-workflow", "dynamic", SCHEMA + "changed" if failure == "schema" else SCHEMA,
                                             revision=1 if failure == "historical" else 0)
        assert all(payload["operation"] != "save" for payload in client.paths)
    finally:
        close(fence, token)
