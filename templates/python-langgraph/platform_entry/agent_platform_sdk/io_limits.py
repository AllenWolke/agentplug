"""Per-event-loop process limits shared by concurrent batches, without global asyncio loop binding."""
from __future__ import annotations
import asyncio,weakref
from collections import deque

_pools=weakref.WeakKeyDictionary()


def shared_io_limit(namespace:str,kind:str,maximum:int,*,run_key:str|None=None,
                    process_maximum:int|None=None):
    if not namespace or kind not in {'read','model','persist'} or type(maximum) is not int or not 1<=maximum<=64:
        raise ValueError('explicit bounded I/O limit required')
    loop=asyncio.get_running_loop();pools=_pools.setdefault(loop,{})
    if run_key is not None or process_maximum is not None:
        if (not isinstance(run_key,str) or not run_key or len(run_key)>1024
                or type(process_maximum) is not int or not maximum<=process_maximum<=64):
            raise ValueError('bounded run and process I/O limits required')
        key=(namespace,kind,'grouped')
        existing=pools.get(key)
        scheduler=existing[1]() if existing is not None else None
        if scheduler is None:
            scheduler=_GroupedLimit(process_maximum)
            pools[key]=(process_maximum,weakref.ref(scheduler))
        elif existing[0]!=process_maximum:
            raise ValueError('process I/O limits cannot change while runs share a loop')
        return _RunLimit(scheduler,run_key,maximum)
    key=(namespace,kind)
    existing=pools.get(key)
    semaphore=existing[1]() if existing is not None else None
    if semaphore is None:
        semaphore=asyncio.Semaphore(maximum);pools[key]=(maximum,weakref.ref(semaphore));return semaphore
    if existing[0]!=maximum:
        raise ValueError('process I/O limits cannot change while batches share a loop')
    return semaphore


class _GroupedLimit:
    """Round-robin queued runs, bounded globally and per run.

    One loop owns every mutation; no task holds a global permit while waiting
    for a run permit. Queued cancellation and cancellation after grant both
    return capacity. Run entries disappear when idle, so run IDs cannot leak.
    These are local scheduling limits; public platform capacity leases still
    enforce deployment/provider-wide admission across processes.
    """
    def __init__(self,maximum):
        self.maximum=maximum
        self.active=0
        self.runs={}
        self.ready=deque()
        self.holders={}

    async def acquire(self,key,maximum):
        task=asyncio.current_task()
        if task in self.holders:
            raise RuntimeError('nested acquisition of the same I/O pool')
        run=self.runs.get(key)
        if run is None:
            run=self.runs[key]={'maximum':maximum,'active':0,'queue':deque()}
        elif run['maximum']!=maximum:
            raise ValueError('run I/O limits cannot change while active')
        future=asyncio.get_running_loop().create_future()
        if not run['queue']:
            self.ready.append(key)
        run['queue'].append((future,task))
        self._pump()
        try:
            await asyncio.shield(future)
        except BaseException:
            if future.done() and not future.cancelled():
                self.release(key,task)
            else:
                future.cancel()
                self._pump()
            raise

    def release(self,key,task):
        if self.holders.pop(task,None)!=key:
            raise RuntimeError('I/O permit owner mismatch')
        self.active-=1
        run=self.runs[key]
        run['active']-=1
        if not run['active'] and not run['queue']:
            del self.runs[key]
        self._pump()

    def _pump(self):
        stalled=0
        while self.ready:
            key=self.ready.popleft()
            run=self.runs[key]
            queue=run['queue']
            while queue and queue[0][0].cancelled():
                queue.popleft()
            if not queue:
                if not run['active']:
                    del self.runs[key]
                stalled=0
                continue
            if self.active>=self.maximum or run['active']>=run['maximum']:
                self.ready.append(key)
                stalled+=1
                if stalled>=len(self.ready):
                    return
                continue
            future,task=queue.popleft()
            self.active+=1
            run['active']+=1
            self.holders[task]=key
            if queue:
                self.ready.append(key)
            future.set_result(None)
            stalled=0


class _RunLimit:
    def __init__(self,pool,key,maximum):
        self.pool,self.key,self.maximum=pool,key,maximum

    async def __aenter__(self):
        await self.pool.acquire(self.key,self.maximum)
        return self

    async def __aexit__(self,*exc):
        self.pool.release(self.key,asyncio.current_task())
