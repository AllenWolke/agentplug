"""Lifespan-owned connection reuse, with isolated per-call headers/cookies.

This caches only sockets. Every request still builds and signs its envelope,
renews its live credential, and passes the platform's current authority gates.
Explicit transports and clients outside a managed lifespan retain old behavior.
"""
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import asyncio
import logging
from weakref import WeakKeyDictionary

import httpx


@dataclass
class _Pool:
    owners: int = 1
    active: bool = True
    transports: dict = field(default_factory=dict)


_pools = WeakKeyDictionary()
_logger = logging.getLogger(__name__)


class _Borrowed(httpx.AsyncBaseTransport):
    def __init__(self, owner, transport):
        self.owner, self.transport = owner, transport

    async def handle_async_request(self, request):
        if not self.owner.active:
            raise RuntimeError("capability connection lifespan closed")
        return await self.transport.handle_async_request(request)

    async def aclose(self):
        # AsyncClient owns its headers/cookies; the lifespan owns its sockets.
        pass


def connection_transport(base_url, explicit=None):
    if explicit is not None:
        return explicit
    owner = _pools.get(asyncio.get_running_loop())
    if owner is None or not owner.active:
        return None
    url = httpx.URL(base_url)
    if url.scheme not in {"http", "https"} or not url.host or url.userinfo:
        return None
    origin = (url.scheme, url.host, url.port)
    transport = owner.transports.get(origin)
    if transport is None:
        if len(owner.transports) >= 8:
            return None  # bounded ownership; do not evict active transports
        transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0,
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=32, keepalive_expiry=5))
        owner.transports[origin] = transport
    return _Borrowed(owner, transport)


@asynccontextmanager
async def capability_connection_lifespan():
    loop = asyncio.get_running_loop()
    owner = _pools.get(loop)
    if owner is None:
        owner = _pools[loop] = _Pool()
    else:
        owner.owners += 1
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        owner.owners -= 1
        if owner.owners == 0:
            owner.active = False
            _pools.pop(loop, None)
            # Close every owned transport even if one close raises. The caller
            # shuts down tracked executions before exiting this lifespan.
            outcomes = await asyncio.gather(*(item.aclose() for item in owner.transports.values()), return_exceptions=True)
            owner.transports.clear()
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    if primary is None:
                        raise outcome
                    _logger.warning("capability_connection_close_failed error_type=%s", type(outcome).__name__)
