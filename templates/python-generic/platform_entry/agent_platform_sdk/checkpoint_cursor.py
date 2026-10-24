"""Bounded durable progress for ordered, independently receipted operations.

The cursor is business progress, never proof of a provider effect or payment.
Callers reconcile a pending item through its existing tool/model workflow.
Only the public State client owns CAS, authority, scope and recovery fencing.
"""
import copy
import hashlib
import re

from .capability_client import GatewayError
from .checkpoint_capacity import reply_limit

NAMESPACE = "checkpoint-cursor"
SCHEMA = "schema://agentplug/checkpoint-cursor/v1"
_EMPTY = hashlib.sha256(b"").hexdigest()
_HASH = re.compile(r"[a-f0-9]{64}")


def _deny(code="CURSOR_STATE_REJECTED"):
    return GatewayError(code,"ordered checkpoint progress is unavailable")


class CheckpointCursor:
    def __init__(self,client,key,state,revision):
        self.client,self.key,self._state,self.revision=client,key,state,revision

    @classmethod
    async def open(cls,client,*,key,input_hash,total):
        if (not isinstance(key,str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",key) is None
                or not isinstance(input_hash,str) or _HASH.fullmatch(input_hash) is None
                or type(total) is not int or not 0<=total<=1000):
            raise _deny("CURSOR_CONFIG_INVALID")
        loaded=await client.load_checkpoint(NAMESPACE,key,SCHEMA)
        limit=reply_limit(loaded)
        # Initial progress plus pending/confirmed transitions for each item.
        # Fail before any effect rather than stop halfway at the old64 bound.
        if 2*total+1>limit:
            raise _deny("CURSOR_CAPACITY_INSUFFICIENT")
        checkpoint=loaded.get("checkpoint")
        if checkpoint is None:
            state={"version":"checkpoint-cursor/v1","input_hash":input_hash,"total":total,
                   "index":0,"phase":"completed" if total==0 else "ready","result_digest":_EMPTY}
            cursor=cls(client,key,state,0)
            await cursor._save(state)
            return cursor
        revision,state=checkpoint.get("revision"),checkpoint.get("value")
        if (type(revision) is not int or not 1<=revision<=limit or not isinstance(state,dict)
                or set(state)!={"version","input_hash","total","index","phase","result_digest"}
                or state["version"]!="checkpoint-cursor/v1" or state["input_hash"]!=input_hash
                or type(state["total"]) is not int or state["total"]!=total
                or type(state["index"]) is not int or not 0<=state["index"]<=total
                or state["phase"] not in {"ready","pending","completed"}
                or (state["phase"]=="completed")!=(state["index"]==total)
                or not isinstance(state["result_digest"],str) or _HASH.fullmatch(state["result_digest"]) is None
                or state["index"]==0 and state["result_digest"]!=_EMPTY):
            raise _deny()
        expected=2*state["index"]+(2 if state["phase"]=="pending" else 1)
        if revision!=expected:
            raise _deny()
        return cls(client,key,copy.deepcopy(state),revision)

    @property
    def index(self):
        return self._state["index"]

    @property
    def completed(self):
        return self._state["phase"]=="completed"

    async def begin(self):
        if self.completed:
            raise _deny("CURSOR_ALREADY_COMPLETED")
        if self._state["phase"]=="pending":
            await self.client.validate_current_execution()
            return True  # caller must use the original receipted operation
        # The public State write rechecks live authority and the same CAS in
        # its commit transaction. A separate preflight cannot strengthen that
        # fence and would add one gateway round trip per new ordered item.
        await self._save({**self._state,"phase":"pending"})
        return False

    async def confirm(self,result_hash):
        if self._state["phase"]!="pending" or not isinstance(result_hash,str) or _HASH.fullmatch(result_hash) is None:
            raise _deny("CURSOR_CONFIRMATION_REJECTED")
        index=self.index+1
        chain=hashlib.sha256(f"{self._state['result_digest']}:{self.index}:{result_hash}".encode()).hexdigest()
        await self._save({**self._state,"index":index,"phase":"completed" if index==self._state["total"] else "ready","result_digest":chain})

    async def _save(self,state):
        receipt=await self.client.save_checkpoint(NAMESPACE,self.key,SCHEMA,copy.deepcopy(state),
            self.revision,f"cursor-{self.revision+1}")
        checkpoint=receipt.get("checkpoint",{})
        if checkpoint.get("revision")!=self.revision+1 or checkpoint.get("value")!=state:
            raise _deny()
        # A lost response never changes the local cursor or authorises a retry.
        self._state=copy.deepcopy(state)
        self.revision+=1
