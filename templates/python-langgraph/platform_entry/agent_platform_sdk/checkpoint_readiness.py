"""Shared read-only readiness probe for the dedicated workflow database."""
import asyncio
import os
from .checkpoint import PostgresCheckpointProvider

async def wait_for_schema(attempts: int=300,delay: float=2.0) -> None:
    if not 1<=attempts<=300 or not 0<=delay<=60:
        raise ValueError('invalid checkpoint readiness retry limits')
    from psycopg import OperationalError
    for attempt in range(attempts):
        provider=PostgresCheckpointProvider(os.getenv('CHECKPOINT_DSN',''))
        try:
            await provider.get()
            return
        except RuntimeError as error:
            # Only transient connection/uninitialized states are retried;
            # drift, incompatible structure and excessive privileges fail closed.
            if str(error) not in {'PostgreSQL checkpoint connection or initialization failed','Checkpoint schema requires the separate bootstrap command before runtime startup'}:
                raise
        finally:
            await provider.close()
        if attempt+1<attempts: await asyncio.sleep(delay)
    raise RuntimeError('Checkpoint schema did not become ready')

if __name__=='__main__':
    asyncio.run(wait_for_schema(), loop_factory=asyncio.SelectorEventLoop if os.name == "nt" else asyncio.new_event_loop)
