"""Durable exact-generation supervision receipts; absence never proves exit."""
from __future__ import annotations
import asyncio
import hashlib
from typing import Protocol
from .errors import DomainExecutionError

SCHEMA_SQL = """CREATE TABLE IF NOT EXISTS public.sdk_execution_generation (
 generation_sha256 varchar(64) PRIMARY KEY CHECK (generation_sha256 ~ '^[0-9a-f]{64}$'),
 receipt_version integer NOT NULL CHECK (receipt_version=1),
 owner_id uuid NOT NULL,
 status varchar(16) NOT NULL CHECK (status IN ('active','exited','stopped')),
 admitted_at timestamptz NOT NULL,
 exited_at timestamptz,
 CHECK ((status='active' AND exited_at IS NULL) OR (status IN ('exited','stopped') AND exited_at IS NOT NULL))
)"""

class GenerationExitStore(Protocol):
    async def admit(self, key: str, owner: str) -> None: ...
    async def exit(self, key: str, owner: str) -> None: ...
    async def stop_exited(self, key: str) -> bool: ...

class PostgresGenerationExitStore:
    """Persist observed exits, including across graceful process/container restarts.

    A crashed task with no exit receipt remains active/unknown. Neither an
    expired lease nor absence of a local task is sufficient to acknowledge it.
    Runtime performs no DDL and holds no platform database credentials.
    """
    def __init__(self, dsn: str):
        from .checkpoint import validate_checkpoint_dsn
        validate_checkpoint_dsn(dsn)
        self._dsn=dsn

    async def _query(self, statement: str, parameters: tuple):
        from psycopg import AsyncConnection
        from psycopg.rows import tuple_row
        try:
            async with asyncio.timeout(4):
                async with await AsyncConnection.connect(
                    self._dsn, connect_timeout=3, autocommit=True,
                    options='-c statement_timeout=3000 -c lock_timeout=1000',
                    row_factory=tuple_row
                ) as conn:
                    from .checkpoint_privileges import validate_checkpoint_grants
                    await validate_checkpoint_grants(conn)
                    cursor=await conn.execute(statement, parameters)
                    return await cursor.fetchone()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never disclose DSN, credentials or upstream exception messages.
            raise DomainExecutionError('CANCELLATION_NOT_CONFIRMED') from None

    async def admit(self, key: str, owner: str) -> None:
        row=await self._query("""INSERT INTO public.sdk_execution_generation
          (generation_sha256,receipt_version,owner_id,status,admitted_at,exited_at)
          VALUES (%s,1,%s,'active',clock_timestamp(),NULL)
          ON CONFLICT (generation_sha256) DO UPDATE
          SET owner_id=EXCLUDED.owner_id,status='active',admitted_at=EXCLUDED.admitted_at,exited_at=NULL
          WHERE sdk_execution_generation.status='exited' AND sdk_execution_generation.receipt_version=1
          RETURNING 1""",(hashlib.sha256(key.encode()).hexdigest(),owner))
        if row is None:
            raise DomainExecutionError('EXECUTION_ALREADY_ACTIVE')

    async def exit(self, key: str, owner: str) -> None:
        row=await self._query("""UPDATE public.sdk_execution_generation
          SET status='exited',exited_at=clock_timestamp()
          WHERE generation_sha256=%s AND owner_id=%s AND receipt_version=1 AND status='active'
          RETURNING 1""",(hashlib.sha256(key.encode()).hexdigest(),owner))
        if row is None:
            raise DomainExecutionError('CANCELLATION_NOT_CONFIRMED')

    async def stop_exited(self, key: str) -> bool:
        row=await self._query("""UPDATE public.sdk_execution_generation SET status='stopped'
          WHERE generation_sha256=%s AND receipt_version=1 AND status IN ('exited','stopped') AND exited_at IS NOT NULL
          RETURNING 1""",
          (hashlib.sha256(key.encode()).hexdigest(),))
        return row is not None
