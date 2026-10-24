"""Parent deadlines cover the whole retrieval observation, including checkpoints."""
import asyncio
from pathlib import Path
import time

import pytest

from agent_platform_sdk.capability_client import GatewayError
from agent_platform_sdk.durable_stage import DurableStageClient
from agent_platform_sdk.knowledge_search import run_knowledge_search


class ReceiptClient:
    def __init__(self):
        self.options = []

    async def run_knowledge_search(self, *args, **kwargs):
        self.options.append(kwargs)
        return {"references": [], "recovery_only": kwargs["recovery_only"]}

    async def run_harness(self, *args, **kwargs):
        self.options.append(kwargs)
        return {'status': 'completed', 'output': {'text': '{}', 'usage': {}}, 'execution': {}}


@pytest.mark.asyncio
async def test_chat_observer_preserves_parent_time_for_route_disposition_and_fallback():
    client = ReceiptClient()
    stage = DurableStageClient(client, key='question', deadline_ms=int(time.time() * 1000) + 55000)
    await stage.chat([{'role': 'user', 'content': 'original question'}])
    assert 50 < client.options[-1]['timeout'] <= 55
    original_key = client.options[-1]['key']
    await stage.chat([{'role': 'user', 'content': 'original question'}], timeout=7)
    assert client.options[-1]['timeout'] == 7
    assert client.options[-1]['key'] == original_key
    stage.deadline_ms = int(time.time() * 1000) - 100
    await stage.chat([{'role': 'user', 'content': 'original question'}])
    assert client.options[-1]['timeout'] == 30
    assert client.options[-1]['deadline_ms'] == stage.deadline_ms


@pytest.mark.asyncio
@pytest.mark.parametrize('timeout', [True, 0, -1, float('nan'), float('inf')])
async def test_chat_invalid_observer_never_dispatches(timeout):
    client = ReceiptClient()
    stage = DurableStageClient(client, key='question', deadline_ms=int(time.time() * 1000) + 55000)
    with pytest.raises(ValueError, match='observation timeout'):
        await stage.chat([{'role': 'user', 'content': 'question'}], timeout=timeout)
    assert client.options == []


@pytest.mark.asyncio
async def test_default_observer_uses_parent_remaining_time_instead_of_thirty_second_clamp():
    client = ReceiptClient()
    stage = DurableStageClient(client, key="question", deadline_ms=int(time.time() * 1000) + 55000)
    await stage.search_knowledge("rule", "scope", as_of="2026-01-31")
    assert 50 < client.options[0]["timeout"] <= 55
    assert client.options[0]["recovery_only"] is False


@pytest.mark.asyncio
async def test_explicit_shorter_timeout_is_kept_and_expired_parent_can_only_recover():
    client = ReceiptClient()
    stage = DurableStageClient(client, key="question", deadline_ms=int(time.time() * 1000) + 55000)
    await stage.search_knowledge("rule", "scope", timeout=7, as_of="2026-01-31")
    assert client.options[-1]["timeout"] == 7
    stage.deadline_ms = int(time.time() * 1000) - 100
    await stage.search_knowledge("rule", "scope", as_of="2026-01-31")
    assert client.options[-1]["timeout"] == 30
    assert client.options[-1]["recovery_only"] is True
    assert client.options[0]["key"] == client.options[1]["key"]


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), float("inf")])
async def test_invalid_observation_limit_never_dispatches(timeout):
    client = ReceiptClient()
    stage = DurableStageClient(client, key="question", deadline_ms=int(time.time() * 1000) + 55000)
    with pytest.raises(GatewayError, match="KNOWLEDGE_SEARCH_CONFIG_INVALID"):
        await stage.search_knowledge("rule", "scope", timeout=timeout, as_of="2026-01-31")
    assert client.options == []


class SlowCheckpointClient:
    def __init__(self):
        self.checkpoint = None
        self.delay = .1
        self.sends = self.recoveries = 0

    async def load_checkpoint(self, *args, **kwargs):
        await asyncio.sleep(self.delay)
        return {"checkpoint": self.checkpoint}

    async def save_checkpoint(self, namespace, key, schema, value, revision, operation_key, **kwargs):
        await asyncio.sleep(self.delay)
        self.checkpoint = {"revision": revision + 1, "value": dict(value)}
        return {"checkpoint": self.checkpoint}

    async def search_knowledge(self, *args, recovery_only=False, **kwargs):
        if recovery_only:
            self.recoveries += 1
        else:
            self.sends += 1
        await asyncio.sleep(self.delay)
        return {"references": [], "recovery_only": recovery_only, "model_requests_sent": 0}

    async def run_knowledge_search(self, *args, **kwargs):
        return await run_knowledge_search(self, *args, **kwargs)


@pytest.mark.asyncio
async def test_checkpoint_and_search_share_one_budget_and_lost_reply_is_only_reconciled():
    client = SlowCheckpointClient()
    stage = DurableStageClient(client, key="question", deadline_ms=int(time.time() * 1000) + 55000)
    with pytest.raises(GatewayError, match="UPSTREAM_TIMEOUT"):
        await stage.search_knowledge("rule", "scope", timeout=.25, as_of="2026-01-31")
    assert client.checkpoint["value"]["phase"] == "dispatch"
    assert client.sends == 1 and stage.receipts == {}
    client.delay = 0
    stage.deadline_ms = int(time.time() * 1000) - 100
    assert (await stage.search_knowledge("rule", "scope", as_of="2026-01-31"))["recovery_only"] is True
    assert client.sends == client.recoveries == 1


@pytest.mark.asyncio
async def test_expired_parent_without_child_state_never_starts_search():
    client = SlowCheckpointClient()
    client.delay = 0
    stage = DurableStageClient(client, key="question", deadline_ms=int(time.time() * 1000) - 100)
    with pytest.raises(GatewayError, match="KNOWLEDGE_RECONCILIATION_REQUIRED"):
        await stage.search_knowledge("rule", "scope", as_of="2026-01-31")
    assert client.sends == client.recoveries == 0 and client.checkpoint is None


def test_durable_stage_template_copies_match_public_sdk():
    root = Path(__file__).resolve().parents[3]
    source = (root / "sdk/python/agent_platform_sdk/durable_stage.py").read_bytes()
    for template in ("python-generic", "python-langgraph"):
        assert (root / "templates" / template / "platform_entry/agent_platform_sdk/durable_stage.py").read_bytes() == source
