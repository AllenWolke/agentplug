"""Explicit PostgreSQL workflow schema bootstrap; never run by Agent requests."""
import asyncio
import os
from .checkpoint import PostgresCheckpointProvider

async def _checkpoint_schema_exists() -> bool:
    from psycopg import AsyncConnection
    from .checkpoint import validate_checkpoint_dsn
    from .checkpoint_schema import checkpoint_schema_state
    dsn=os.getenv('CHECKPOINT_DSN','')
    validate_checkpoint_dsn(dsn,runtime=False)
    async with await AsyncConnection.connect(dsn,autocommit=True) as connection:
        return await checkpoint_schema_state(connection,'public')=='ready'

async def main() -> None:
    provider=PostgresCheckpointProvider(os.getenv('CHECKPOINT_DSN'))
    try:
        await provider.initialize_schema()
    finally:
        await provider.close()
    from psycopg import AsyncConnection
    from .generation_exit import SCHEMA_SQL
    async with await AsyncConnection.connect(os.getenv('CHECKPOINT_DSN'), autocommit=True) as connection:
        await connection.execute(SCHEMA_SQL)
    print('checkpoint schema initialized; execution exit receipt schema initialized')

if __name__=='__main__':
    asyncio.run(main(), loop_factory=asyncio.SelectorEventLoop if os.name == "nt" else asyncio.new_event_loop)
