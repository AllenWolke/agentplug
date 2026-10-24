import json
from pathlib import Path

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.checkpoint_capacity import reply_limit


def test_shared_capacity_contract():
    fixture = json.loads((Path(__file__).resolve().parents[3] / "contracts/fixtures/public-capabilities-v1.json").read_text(encoding="utf-8"))
    for case in fixture["capacity"]:
        if "error" in case:
            with pytest.raises(GatewayError) as error:
                reply_limit(case["reply"])
            assert error.value.code == case["error"]
        else:
            assert reply_limit(case["reply"]) == case["limit"]


@pytest.mark.asyncio
async def test_shared_unknown_model_metadata_survives_chat():
    from types import SimpleNamespace
    from agent_platform_sdk.capability_client import CapabilityGatewayClient
    fixture = json.loads((Path(__file__).resolve().parents[3] / "contracts/fixtures/public-capabilities-v1.json").read_text(encoding="utf-8"))
    metadata = fixture["preserved_model_metadata"]
    class Client(CapabilityGatewayClient):
        def __init__(self):
            self._context = SimpleNamespace(task_id="run", session_id="session", request_id="request")
        async def _post(self, path, payload, timeout):
            assert path == "/internal/model/generate" and payload["idempotency_key"]
            return {"text": "answer", "usage": {}, **metadata}
    result = await Client().chat([{"role": "user", "content": "question"}])
    assert {field: result[field] for field in metadata} == metadata
    assert result["billing"]["amount"] is None
