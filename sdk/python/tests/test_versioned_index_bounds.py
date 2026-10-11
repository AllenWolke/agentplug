import asyncio
import pytest
from agent_platform_sdk.versioned_index import IndexIdentity,PermissionScopedSingleflight

IDENTITY=IndexIdentity('corpus-v1','model-v1','tokenizer-v1','chunks-v1')


@pytest.mark.asyncio
async def test_concurrent_load_coalesces_but_rechecks_each_return():
    cache=PermissionScopedSingleflight(2);gate=asyncio.Event();entered=asyncio.Event();loads=0;checks=0
    async def check():
        nonlocal checks
        checks+=1
    async def load():
        nonlocal loads
        loads+=1;entered.set();await gate.wait();return b'evidence'
    def invoke(revision='permissions-v1'):
        return cache.get(identity=IDENTITY,scope_identity='actor-a',permission_revision=revision,
                         query='question',load=load,check_current=check)
    owner=asyncio.create_task(invoke());await entered.wait()
    follower=asyncio.create_task(invoke());await asyncio.sleep(0)
    follower.cancel()
    with pytest.raises(asyncio.CancelledError):await follower
    gate.set();assert await owner==b'evidence'
    assert await invoke()==b'evidence'
    assert loads==1 and cache.coalesced==1 and checks>=5
    assert await invoke('permissions-v2')==b'evidence'
    assert loads==2


@pytest.mark.asyncio
async def test_revocation_prevents_cached_and_inflight_results():
    cache=PermissionScopedSingleflight();revoked=False
    async def check():
        if revoked:raise PermissionError('revoked')
    async def load():
        nonlocal revoked
        revoked=True;return b'sensitive'
    with pytest.raises(PermissionError):
        await cache.get(identity=IDENTITY,scope_identity='actor-a',permission_revision='v1',
                        query='q',load=load,check_current=check)
    assert not cache.cache and not cache.inflight


@pytest.mark.asyncio
async def test_failed_owner_is_not_cached_or_replayed():
    cache=PermissionScopedSingleflight();calls=0
    async def check():pass
    async def load():
        nonlocal calls
        calls+=1;raise TimeoutError('unknown outcome')
    with pytest.raises(TimeoutError):
        await cache.get(identity=IDENTITY,scope_identity='actor-a',permission_revision='v1',
                        query='q',load=load,check_current=check)
    assert calls==1 and not cache.cache and not cache.inflight


def test_message_admission_counts_entire_prompt_and_preserves_evidence():
    from agent_platform_sdk.context_admission import admit_messages
    refs=[{'doc_id':'d','document_version':'1','content':'x'*150},
          {'doc_id':'d','document_version':'2','content':'x'*150}]
    def build(items):return [{'role':'system','content':'rules'},
                             {'role':'user','content':'question'+''.join(i['content'] for i in items)}]
    result=admit_messages(refs,build_messages=build,maximum_input_tokens=600)
    assert len(result['references'])==1 and result['measurement']['actual_generation_input_tokens'] is None
    assert result['measurement']['truncated_references']==0
    with pytest.raises(ValueError):
        admit_messages([],build_messages=build,maximum_input_tokens=128)
