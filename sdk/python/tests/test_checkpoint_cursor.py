"""Crash/acknowledgement semantics for bounded progress, not fake model scores."""
import copy

import pytest

from agent_platform_sdk import CheckpointCursor
from agent_platform_sdk.capability_client import GatewayError

HISTORY={"version":"checkpoint-history/v1","max_revisions":4096}
HASH="a"*64


class Client:
    def __init__(self):
        self.cp=None
        self.saves=[]
        self.metadata=copy.deepcopy(HISTORY)
        self.failure=None
        self.denied=False
        self.validations=0
    async def load_checkpoint(self,*args):
        result={"checkpoint":copy.deepcopy(self.cp)}
        if self.metadata is not None: result["checkpoint_history"]=self.metadata
        return result
    async def validate_current_execution(self):
        self.validations+=1
        if self.denied:raise GatewayError("CAPABILITY_DENIED","revoked")
    async def save_checkpoint(self,namespace,key,schema,value,expected,operation):
        if self.denied:raise GatewayError("CAPABILITY_DENIED","revoked")
        assert expected==(0 if self.cp is None else self.cp["revision"])
        if self.failure=="before-commit" and value["index"]>0:
            self.failure=None
            raise GatewayError("STATE_RESULT_UNKNOWN","ack unavailable")
        self.cp={"revision":expected+1,"value":copy.deepcopy(value),"schema_id":schema}
        self.saves.append((operation,copy.deepcopy(value)))
        if self.failure=="after-commit" and value["index"]>0:
            self.failure=None
            raise GatewayError("STATE_RESULT_UNKNOWN","ack unavailable")
        return {"checkpoint":copy.deepcopy(self.cp)}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure",["before-commit","after-commit"])
async def test_lost_progress_reply_reopens_exact_pending_or_confirmed_head(failure):
    client=Client()
    cursor=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=2)
    assert await cursor.begin() is False
    client.failure=failure
    with pytest.raises(GatewayError):await cursor.confirm("b"*64)
    assert cursor.index==0  # no local advancement after an unconfirmed response
    restored=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=2)
    assert restored.index==(1 if failure=="after-commit" else 0)
    if failure=="before-commit":
        assert await restored.begin() is True  # reconcile original item, never fresh-send blindly
        await restored.confirm("b"*64)
    assert restored.index==1
    assert await restored.begin() is False
    await restored.confirm("c"*64)
    assert restored.completed and restored.index==2 and restored.revision==5
    assert len(client.saves)==5


@pytest.mark.asyncio
async def test_capacity_rejected_before_initialisation_and_effects():
    client=Client();client.metadata=None
    with pytest.raises(GatewayError,match="CURSOR_CAPACITY_INSUFFICIENT"):
        await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=1000)
    assert client.cp is None and client.saves==[]


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation",["input","total","index","revision","phase","digest","extra"])
async def test_input_changes_and_corrupted_progress_cannot_skip_items(mutation):
    client=Client()
    await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=10)
    if mutation=="revision":client.cp["revision"]+=1
    elif mutation=="input":client.cp["value"]["input_hash"]="c"*64
    elif mutation=="total":client.cp["value"]["total"]=9
    elif mutation=="index":client.cp["value"]["index"]=True
    elif mutation=="phase":client.cp["value"]["phase"]="completed"
    elif mutation=="digest":client.cp["value"]["result_digest"]="not-a-hash"
    else:client.cp["value"]["override"]=True
    before=copy.deepcopy(client.saves)
    with pytest.raises(GatewayError):await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=10)
    assert client.saves==before


@pytest.mark.asyncio
async def test_current_revocation_stops_progress_without_changing_head():
    client=Client()
    cursor=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=1)
    client.denied=True
    with pytest.raises(GatewayError,match="CAPABILITY_DENIED"):await cursor.begin()
    assert len(client.saves)==1 and cursor.index==0


@pytest.mark.asyncio
async def test_pending_recovery_still_rechecks_authority_without_rewriting_intent():
    client=Client()
    cursor=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=1)
    assert await cursor.begin() is False
    assert client.validations==0 and len(client.saves)==2
    restored=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=1)
    client.denied=True
    with pytest.raises(GatewayError,match="CAPABILITY_DENIED"):
        await restored.begin()
    assert client.validations==1 and len(client.saves)==2 and restored.index==0


@pytest.mark.asyncio
@pytest.mark.parametrize("total",[100,1000])
async def test_new_items_reuse_state_commit_authority_without_extra_preflight_rpc(total):
    # Component-only call counts, never a service capacity/latency sample.
    client=Client()
    cursor=await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=total)
    for _ in range(total):
        assert await cursor.begin() is False
        await cursor.confirm("b"*64)
    assert cursor.completed and cursor.index==total
    assert len(client.saves)==2*total+1 and client.validations==0


@pytest.mark.asyncio
async def test_empty_and_completed_replay_do_not_dispatch_or_advance():
    client=Client()
    cursor=await CheckpointCursor.open(client,key="empty",input_hash=HASH,total=0)
    assert cursor.completed
    restored=await CheckpointCursor.open(client,key="empty",input_hash=HASH,total=0)
    assert restored.completed and len(client.saves)==1
    with pytest.raises(GatewayError):await restored.begin()


@pytest.mark.asyncio
@pytest.mark.parametrize("total",[-1,1001,True,1.5])
async def test_unbounded_or_ambiguous_total_rejected_before_initialisation(total):
    client=Client()
    with pytest.raises(GatewayError,match="CURSOR_CONFIG_INVALID"):
        await CheckpointCursor.open(client,key="batch",input_hash=HASH,total=total)
    assert client.cp is None and not client.saves
