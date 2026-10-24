import copy
from types import SimpleNamespace
import time

import pytest

from agent_platform_sdk.capability_client import CapabilityGatewayClient
from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.durable_stage import DurableStageClient
from agent_platform_sdk.harness import _budget_output, _limit_output
from agent_platform_sdk.response_schema import schema_request

SCHEMA = {"type": "object", "properties": {"query": {"type": "string", "minLength": 1}},
          "required": ["query"], "additionalProperties": False}


def test_schema_client_bounds_copy_and_legacy():
    schema, mode = schema_request(SCHEMA, "", True)
    assert schema == SCHEMA and schema is not SCHEMA and mode == "required"
    assert schema_request(None, "", False) == (None, "")
    for schema, mode, required in [(SCHEMA, "unknown", True), (SCHEMA, "required", False),
                                   (None, "required", True), ([], "", True),
                                   ({"type": "object", "description": "a"*16385}, "", True)]:
        with pytest.raises(ValueError):
            schema_request(schema, mode, required)


def test_nullable_type_and_real_receipt_are_preserved_without_coercion():
    schema = {"type": "object", "properties": {"value": {"type": ["boolean", "null"]}},
              "required": ["value"], "additionalProperties": False}
    bound, mode = schema_request(schema, "required", True)
    assert bound == schema and mode == "required"
    schema["properties"]["value"]["type"].append("string")
    assert bound["properties"]["value"]["type"] == ["boolean", "null"]
    receipt = {"text": '{"value":null}', "response_schema": {
        "version": "model-response-schema/v1", "requested_mode": "required",
        "applied_format": "json_schema", "wire_protocol": "responses/v1", "strict": True,
        "dialect": "json-schema/responses/v1", "schema_sha256": "a"*64}}
    assert _budget_output(receipt)["response_schema"] == receipt["response_schema"]
    assert _limit_output(receipt, "round_limit")["response_schema"] == receipt["response_schema"]


@pytest.mark.asyncio
async def test_schema_pins_both_chat_and_durable_identity_and_receipt():
    receipt = {"text": '{"query":"valid"}', "usage": {"input_tokens": 7, "output_tokens": 3},
               "response_schema": {"version": "model-response-schema/v1", "applied_format": "json_schema"}}

    class Fixture(CapabilityGatewayClient):
        def __init__(self):
            self._context = SimpleNamespace(prompt_template_hash="published", task_id="run")
            self.requests = []
        async def _post(self, path, payload, timeout):
            self.requests.append(copy.deepcopy(payload))
            return receipt
        async def run_harness(self, request, **kwargs):
            self.requests.append(copy.deepcopy(request))
            return {"status": "completed", "output": receipt, "execution": {"model_calls": 1}}

    client = Fixture()
    facade = DurableStageClient(client, key="same-stage", deadline_ms=int(time.time()*1000)+30000)
    messages = [{"role": "user", "content": "question"}]
    for target in (client, facade):
        a = await target.chat(messages, require_json=True, response_schema=SCHEMA)
        b = await target.chat(messages, require_json=True, response_schema=copy.deepcopy(SCHEMA))
        changed = copy.deepcopy(SCHEMA); changed["properties"]["query"]["minLength"] = 2
        await target.chat(messages, require_json=True, response_schema=changed)
        first, second, third = client.requests[-3:]
        assert first["idempotency_key"] == second["idempotency_key"] != third["idempotency_key"]
        assert first["response_schema"] == SCHEMA and first["response_schema_mode"] == "required"
        assert a["response_schema"] == b["response_schema"] == receipt["response_schema"]
    for output in (_budget_output(receipt), _limit_output(receipt, "round_limit")):
        assert output["response_schema"] == receipt["response_schema"] and output["usage"]["input_tokens"] == 7


@pytest.mark.asyncio
async def test_schema_unknown_receipt_recovers_exact_request_without_resend():
    from test_public_harness import Fixture

    class LostResponse(Fixture):
        async def _post(self, path, command, timeout):
            if path.endswith("model/generate"):
                self.models += 1
                self.saved_schema = copy.deepcopy(command["response_schema"])
                self.model_receipts[command["idempotency_key"]] = {
                    "text": '{"query":"valid"}', "usage": {"input_tokens": 7, "output_tokens": 3},
                    "response_schema": {"version": "model-response-schema/v1", "applied_format": "json_schema"}}
                raise GatewayError("MODEL_RESULT_UNKNOWN", "synthetic lost response")
            if path.endswith("model/receipt"):
                assert command["response_schema"] == self.saved_schema
            return await super()._post(path, command, timeout)

    client = LostResponse()
    request = {"messages": [{"role": "user", "content": "query"}], "idempotency_key": "schema",
               "require_json": True, "response_schema": SCHEMA, "response_schema_mode": "required"}
    with pytest.raises(GatewayError):
        await client.run_harness(request, key="schema-lost")
    assert client.models == 1 and client.checkpoint["value"]["model_request"]["response_schema"] == SCHEMA
    result = await client.run_harness(request, key="schema-lost")
    assert result["status"] == "completed" and client.models == 1 and client.model_queries == 1
    assert result["output"]["response_schema"]["applied_format"] == "json_schema"
