"""冻结只读索引与权限版本化singleflight，供独立Provider/离线实验复用。"""
from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
from collections.abc import Awaitable,Callable
import asyncio,hashlib,json,math,time


@dataclass(frozen=True)
class IndexIdentity:
    corpus_revision: str
    model_revision: str
    tokenizer_revision: str
    chunk_configuration: str

    def digest(self):
        if not all((self.corpus_revision,self.model_revision,self.tokenizer_revision,self.chunk_configuration)):
            raise ValueError('complete immutable index identity required')
        return hashlib.sha256(json.dumps(self.__dict__,sort_keys=True).encode()).hexdigest()


class PermissionScopedSingleflight:
    """授权检查发生在每次返回前后，不以缓存中的旧权限作授权依据。"""
    def __init__(self,maximum=128,ttl_seconds=60):
        if not 1<=maximum<=4096:raise ValueError('bounded cache required')
        if not isinstance(ttl_seconds,(int,float)) or not math.isfinite(ttl_seconds) or not 0<ttl_seconds<=3600:
            raise ValueError('finite cache TTL in (0,3600] required')
        self.ttl_seconds=ttl_seconds
        self.maximum=maximum;self.cache=OrderedDict();self.inflight={};self.lock=asyncio.Lock()
        self.hits=0;self.misses=0;self.coalesced=0
    async def get(self,*,identity:IndexIdentity,scope_identity:str,permission_revision:str,
                  query:str,load:Callable[[],Awaitable[bytes]],check_current:Callable[[],Awaitable[None]])->bytes:
        if not scope_identity or not permission_revision or not query:raise ValueError('scope, live revision and query required')
        await check_current()
        key=(identity.digest(),scope_identity,permission_revision,hashlib.sha256(query.encode()).hexdigest())
        owner=False
        async with self.lock:
            if key in self.cache and self.cache[key][0]<=time.monotonic():self.cache.pop(key)
            if key in self.cache:
                self.hits+=1;value=self.cache[key][1];self.cache.move_to_end(key);future=None
            elif key in self.inflight:
                self.coalesced+=1;future=self.inflight[key];value=None
            else:
                if len(self.inflight)>=self.maximum:raise RuntimeError('SINGLEFLIGHT_CAPACITY_REACHED')
                self.misses+=1;owner=True;future=asyncio.get_running_loop().create_future();self.inflight[key]=future;value=None
        if owner:
            try:
                value=await load()
                if not isinstance(value,bytes) or len(value)>1<<20:raise ValueError('bounded immutable cache value required')
                await check_current()
                async with self.lock:
                    self.cache[key]=(time.monotonic()+self.ttl_seconds,value)
                    while len(self.cache)>self.maximum:self.cache.popitem(last=False)
                    future.set_result(value)
            except BaseException as error:
                if not future.done():
                    future.set_exception(error);future.exception()
                raise
            finally:
                async with self.lock:self.inflight.pop(key,None)
        elif future is not None:
            # 一个等待者取消不取消共享请求；owner取消则所有等待者明确失败。
            value=await asyncio.shield(future)
        await check_current()
        return value
