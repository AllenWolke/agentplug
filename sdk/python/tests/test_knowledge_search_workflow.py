import copy
import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.knowledge_search import run_knowledge_search, STATE_SCHEMA


class Client:
    def __init__(self):
        self.checkpoint = None
        self.calls = self.reads = 0
        self.fail = False
        self.unknown = False
        self.forbidden = False
        self.receipt = {"references": [{"doc_id": "history", "content": "effective evidence"}],
                        "retrieved_sources": [], "failed_sources": []}

    async def load_checkpoint(self, *args, **kwargs):
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def save_checkpoint(self, namespace, key, schema, value, expected, operation_key, **kwargs):
        assert namespace == "knowledge-search" and schema == STATE_SCHEMA
        assert operation_key == f"search-{expected + 1}"
        assert expected == (self.checkpoint or {}).get("revision", 0)
        self.checkpoint = {"revision": expected + 1, "value": copy.deepcopy(value)}
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def search_knowledge(self, query, scope, **kwargs):
        assert kwargs["as_of"] == "2026-01-31" and kwargs["source_ids"] == ["authorized"]
        if self.forbidden:
            raise GatewayError("KNOWLEDGE_DOCUMENTS_DENIED", "fixed")
        if kwargs["recovery_only"]:
            self.reads += 1
            if self.unknown:
                raise GatewayError("KNOWLEDGE_RECONCILIATION_REQUIRED", "fixed")
            return {**copy.deepcopy(self.receipt), "recovery_only": True, "model_requests_sent": 0}
        self.calls += 1
        if self.fail:
            raise GatewayError("MODEL_RESULT_UNKNOWN", "fixed")
        return copy.deepcopy(self.receipt)


async def run(client, **kwargs):
    return await run_knowledge_search(client, "historical rule", "scope", key="search", as_of="2026-01-31",
                                     source_ids=["authorized"], **kwargs)


@pytest.mark.asyncio
async def test_search_finished_replay_freshly_authorizes_and_sends_no_model_request():
    client = Client()
    await run(client)
    assert (await run(client))["recovery_only"] is True
    assert client.calls == client.reads == 1
    client.forbidden = True
    with pytest.raises(GatewayError, match="KNOWLEDGE_DOCUMENTS_DENIED"):
        await run(client)
    assert client.calls == 1


@pytest.mark.asyncio
async def test_lost_reply_uses_search_receipt_route_without_new_charge():
    client = Client()
    client.fail = True
    with pytest.raises(GatewayError, match="MODEL_RESULT_UNKNOWN"):
        await run(client)
    assert client.checkpoint["value"]["phase"] == "dispatch"
    assert (await run(client))["model_requests_sent"] == 0
    assert client.calls == client.reads == 1


@pytest.mark.asyncio
async def test_unknown_or_absent_child_state_never_starts_replacement_search():
    client = Client()
    with pytest.raises(GatewayError, match="KNOWLEDGE_RECONCILIATION_REQUIRED"):
        await run(client, recovery_only=True)
    assert client.calls == 0
    client.fail = True
    with pytest.raises(GatewayError, match="MODEL_RESULT_UNKNOWN"):
        await run(client)
    client.unknown = True
    with pytest.raises(GatewayError, match="KNOWLEDGE_RECONCILIATION_REQUIRED"):
        await run(client)
    assert client.calls == 1


@pytest.mark.asyncio
async def test_empty_evidence_is_a_known_result_not_a_cancelled_regulation():
    client = Client()
    client.receipt["references"] = []
    assert (await run(client))["references"] == []
    assert client.checkpoint["value"]["phase"] == "completed"


@pytest.mark.asyncio
async def test_business_date_and_source_selection_are_bound_to_state_identity():
    client = Client()
    await run(client)
    for patch in ({"as_of": "2026-02-28"}, {"source_ids": ["other"]}):
        arguments = {"key": "search", "as_of": "2026-01-31", "source_ids": ["authorized"], **patch}
        with pytest.raises(GatewayError, match="KNOWLEDGE_SEARCH_STATE_REJECTED"):
            await run_knowledge_search(client, "historical rule", "scope", **arguments)
    assert client.calls == 1
