"""Per-event-loop process limits shared by concurrent batches, without global asyncio loop binding."""
from __future__ import annotations
import asyncio,weakref

_pools=weakref.WeakKeyDictionary()


def shared_io_limit(namespace:str,kind:str,maximum:int)->asyncio.Semaphore:
    if not namespace or kind not in {'read','model','persist'} or type(maximum) is not int or not 1<=maximum<=64:
        raise ValueError('explicit bounded I/O limit required')
    loop=asyncio.get_running_loop();pools=_pools.setdefault(loop,{})
    key=(namespace,kind)
    existing=pools.get(key)
    semaphore=existing[1]() if existing is not None else None
    if semaphore is None:
        semaphore=asyncio.Semaphore(maximum);pools[key]=(maximum,weakref.ref(semaphore));return semaphore
    if existing[0]!=maximum:
        raise ValueError('process I/O limits cannot change while batches share a loop')
    return semaphore
