import copy
import json
from pathlib import Path
import pytest

from agent_platform_sdk.checkpoint_reference_set import digest, runtime_parts
from agent_platform_sdk.execution_lifecycle import ExecutionLifecycle
from agent_platform_sdk.errors import DomainExecutionError
from test_graph_recovery import request, Client, Graph, CONFIG, recovery
from agent_platform_sdk.graph_recovery import PublicGraphCheckpointBridge


class PagedClient(Client):
    def __init__(self, req):
        super().__init__(req)
        self.references = []
        self.group = None
        self.pages = []
        self.tamper = ""
    async def _post(self, path, command, timeout):
        assert path == "/internal/state/checkpoint" and command["operation"] == "load"
        assert command["reference_set"] == self.group and command["limit"] == 64
        offset = command["offset"]
        self.pages.append(offset)
        result = {"version":"recovery-checkpoint-page/v1", "set":self.group, "offset":offset,
            "references":copy.deepcopy(self.references[offset:offset+64])}
        if self.tamper == "offset": result["offset"] += 1
        if self.tamper == "count": result["references"] = []
        if self.tamper == "hash": result["references"][0]["content_hash"] = "9"*64
        if self.tamper == "scope": result["set"] = {**self.group, "digest":"9"*64}
        return result


async def prepared():
    original = request()
    client, graph = PagedClient(original), Graph(original)
    async def work():
        graph.complete()
        return graph.snapshot.values
    await PublicGraphCheckpointBridge().execute(original, client, graph, CONFIG, work)
    restored = recovery(original, client)
    root = restored.resume_input["reference"]["checkpoints"][0]
    references = [{**root, "state_key":format(i, "064x")} for i in range(128)] + [root]
    client.references = sorted(references, key=lambda ref: ref["state_key"])
    client.group = {"version":"recovery-checkpoint-set/v1", "count":len(references), "digest":digest(client.references)}
    restored.resume_input["version"] = "runtime-recovery/v2"
    reference = restored.resume_input["reference"]
    reference["version"], reference["checkpoint_set"] = "runtime-recovery-stop/v2", client.group
    del reference["checkpoints"]
    return restored, client, graph


@pytest.mark.asyncio
async def test_verified_pages_keep_completed_graph_read_only_and_do_not_load_unvisited_values():
    req, client, graph = await prepared()
    output = await PublicGraphCheckpointBridge().execute(req, client, graph, CONFIG,
        lambda: pytest.fail("completed graph must not redispatch business work"))
    assert output["answer"]["facts_supported"] and graph.calls == []
    assert client.pages == [0, 64, 128]
    assert req.resume_input["version"] == "runtime-recovery/v2" and "checkpoints" not in req.resume_input["reference"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["offset", "count", "hash", "scope"])
async def test_page_tampering_never_reaches_graph_execution(tamper):
    req, client, graph = await prepared()
    client.tamper = tamper
    with pytest.raises(DomainExecutionError):
        await PublicGraphCheckpointBridge().execute(req, client, graph, CONFIG,
            lambda: pytest.fail("unverified page reached work"))
    assert graph.calls == [] and len(client.writes) == 2


@pytest.mark.asyncio
async def test_unordered_expired_duplicate_and_oversized_sets_are_rejected():
    for scenario in ("unordered", "expired", "duplicate", "large"):
        req, client, graph = await prepared()
        if scenario == "large":
            client.group["count"] = 8193
        else:
            if scenario == "unordered": client.references.reverse()
            if scenario == "expired": client.references[0]["expires_at"] = "2000-01-01T00:00:00Z"
            if scenario == "duplicate": client.references[1] = copy.deepcopy(client.references[0])
            client.group["digest"] = digest(client.references)
        identity = ExecutionLifecycle._identity(req)
        with pytest.raises(DomainExecutionError):
            await runtime_parts(req, client, identity, 5)


def test_cross_language_reference_digest():
    fixture = json.loads((Path(__file__).resolve().parents[3] / "contracts/fixtures/recovery-checkpoint-set-v1.json").read_text(encoding="utf-8"))
    assert digest(fixture["references"]) == fixture["set"]["digest"]
