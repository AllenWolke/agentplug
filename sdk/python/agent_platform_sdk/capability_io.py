"""Apply shared I/O limits at individual gateway send boundaries."""
import asyncio
import math
import time
from functools import partial
from .capability_client import CapabilityGatewayClient
from .io_limits import shared_io_limit


class LimitedCapabilityClient(CapabilityGatewayClient):
    """Transient facade; the original client retains signing, IAM and receipts.

    Limiting the entire orchestration holds model capacity while tools, State
    and retrieval wait. Route limits instead protect actual concurrent sends.
    """
    def __init__(self, client, route_limits):
        self._client, self._route_limits = client, dict(route_limits)
        self._context = client._context

    def __getattr__(self, name):
        return getattr(self._client, name)

    @classmethod
    def for_run(cls, client, namespace, run_key, routes):
        """Bind immutable local bounds; create loop-owned pools only on use.

        routes maps a gateway path to (kind, run maximum, process maximum).
        Construction is safe outside an event loop, like the original client.
        """
        return cls(client, {path: partial(shared_io_limit, namespace, kind, maximum,
            run_key=run_key, process_maximum=process_maximum)
            for path, (kind, maximum, process_maximum) in routes.items()})

    async def _post(self, path, payload, timeout):
        limiter = self._route_limits.get(path)
        if limiter is None:
            return await self._client._post(path, payload, timeout)
        if callable(limiter):
            limiter = limiter()
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("positive bounded gateway timeout required")
        # Waiting for local capacity consumes this RPC's original allowance.
        # The underlying SDK still owns all signing, receipts and observations.
        deadline = time.monotonic() + timeout
        async with asyncio.timeout(timeout):
            async with limiter:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("gateway capacity wait exhausted")
                return await self._client._post(path, payload, remaining)

    async def validate_current_execution(self):
        return await self._client.validate_current_execution()

    async def prepare_context(self, *args, **kwargs):
        return await self._client.prepare_context(*args, **kwargs)

    async def load_checkpoint(self, *args, **kwargs):
        return await self._client.load_checkpoint(*args, **kwargs)

    async def load_recovery_checkpoint(self, *args, **kwargs):
        return await self._client.load_recovery_checkpoint(*args, **kwargs)

    async def save_checkpoint(self, *args, **kwargs):
        return await self._client.save_checkpoint(*args, **kwargs)
