import copy
from types import SimpleNamespace

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.knowledge_harness import run_knowledge_harness


class Client:
    def __init__(self):
        self._context = SimpleNamespace(task_id="run")
        self.checkpoint = None
        self.calls = []
        self.confirm_read_only = True

    async def load_checkpoint(self, *args, **kwargs):
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def save_checkpoint(self, namespace, key, schema, value, expected, operation, **kwargs):
        assert expected == (self.checkpoint or {}).get("revision", 0)
        self.checkpoint = {"revision": expected + 1, "schema_id": schema, "value": copy.deepcopy(value)}
        return {"checkpoint": copy.deepcopy(self.checkpoint)}

    async def load_skill_bindings(self, ids, **kwargs):
        return {item: {"version_id": "1.0.0", "digest": "a" * 64} for item in ids}

    async def answer_knowledge(self, query, scope, **kwargs):
        self.calls.append(kwargs)
        return {"text": "frozen answer", "references": [{"doc_id": "doc"}], "citation_ids": ["doc"],
                **({"recovery_only": True, "model_requests_sent": 0} if self.confirm_read_only else {})}


async def run(client, **options):
    return await run_knowledge_harness(client, "question", "docs", key="answer",
        skill_requests=[{"skill_id": "guide", "sections": ["citations"]}], **options)


@pytest.mark.asyncio
async def test_dates_and_sources_bind_both_dispatch_and_read_only_recovery():
    client = Client()
    options = {"as_of": "2026-10-22", "source_ids": ["approved-source"]}
    await run(client, **options)
    await run(client, **options)
    assert [call["recovery_only"] for call in client.calls] == [False, True]
    assert all(call["as_of"] == options["as_of"] and call["source_ids"] == options["source_ids"] for call in client.calls)
    for changed in ({"as_of": "2026-10-21"}, {"source_ids": ["different-source"]}):
        with pytest.raises(GatewayError, match="HARNESS_STATE_REJECTED"):
            await run(client, **(options | changed))
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_finished_replay_requires_an_explicit_read_only_receipt():
    client = Client()
    await run(client)
    client.confirm_read_only = False
    with pytest.raises(GatewayError, match="KNOWLEDGE_RECONCILIATION_REQUIRED"):
        await run(client)
    assert [call["recovery_only"] for call in client.calls] == [False, True]
