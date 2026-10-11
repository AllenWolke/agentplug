"""SDK-owned PostgreSQL workflow persistence and trusted scope namespaces."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Any
from urllib.parse import unquote, urlsplit, parse_qs
from .security import DEVELOPMENT_ENVS


def validate_checkpoint_dsn(dsn: str, *, runtime: bool = True) -> None:
    try:
        parsed = urlsplit(dsn)
        user, password = unquote(parsed.username or ''), unquote(parsed.password or '')
        database = unquote(parsed.path.lstrip('/'))
        valid = (parsed.scheme in {'postgres', 'postgresql'} and parsed.hostname and user.strip()
                 and database and '/' not in database and password
                 and not parsed.fragment and set(parse_qs(parsed.query)) <= {'sslmode', 'connect_timeout', 'application_name'})
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            valid = False
        if runtime and user.strip().lower() in {'root', 'postgres'}:
            valid = False
        if os.getenv('APP_ENV', '').strip().lower() not in DEVELOPMENT_ENVS:
            valid = valid and len(password.encode('utf-8')) >= 16 and len(set(password)) > 1 and not any(
                marker in password.lower() for marker in ('replace-', 'change-me', 'changeme', 'placeholder', 'dev-internal', 'dev-signing'))
    except (ValueError, UnicodeError, TypeError):
        valid = False
    if not valid:
        raise RuntimeError('CHECKPOINT_DSN requires an explicit PostgreSQL URL, database and strong password; runtime requires a non-administrator account') from None


def scoped_config(harness: Any) -> dict[str, dict[str, str]]:
    """Build an isolated LangGraph namespace from trusted platform Scope.

    The fields are deliberately read from the verified HarnessContext instead
    of a raw user payload. / 字段必须来自已验证的 HarnessContext，而不是用户
    原始输入，确保同一用户/Agent 的会话也不会跨租户或应用串线。
    """

    raw_thread_id = harness.thread_id or harness.session_id
    if not raw_thread_id:
        raise ValueError("thread_id or session_id is required")
    # Canonical tuple encoding prevents delimiter collisions and binds every
    # persistent identity dimension. Run IDs are excluded for session continuity.
    # 规范元组编码防止分隔符碰撞；不加入 Run ID，以保留同会话跨 Run 连续性。
    dimensions = (
        harness.tenant_id,
        harness.department_id,
        harness.application_id,
        harness.installation_id,
        harness.agent_instance_id,
        harness.agent_id,
        harness.agent_version_id,
        harness.principal_type,
        harness.actor_id,
        raw_thread_id,
    )
    if not all(isinstance(value, str) and value.strip() for value in dimensions):
        raise ValueError("complete trusted checkpoint scope is required")
    encoded = json.dumps(dimensions, ensure_ascii=False, separators=(",", ":"))
    thread_id = "scope-v2:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return {
        "configurable": {
            "thread_id": thread_id,
            # LangGraph reserves checkpoint_ns for subgraphs. Root graphs save
            # in the empty namespace; version isolation belongs in thread_id.
            # LangGraph 将 checkpoint_ns 留给子图；根图固定空命名空间，
            # 版本隔离由规范化 thread_id 保证。
            "checkpoint_ns": "",
            "agent_version_id": harness.agent_version_id,
            "tenant_id": harness.tenant_id,
            "department_id": harness.department_id,
            "application_id": harness.application_id,
            "agent_id": harness.agent_id,
            "actor_id": harness.actor_id,
            "installation_id": harness.installation_id,
            "agent_instance_id": harness.agent_instance_id,
            "principal_type": harness.principal_type,
            "raw_thread_id": raw_thread_id,
        }
    }


class PostgresCheckpointProvider:
    """Lazy shared provider; runtime never applies schema migrations.

    Use a separate workflow database, not the platform identity/business DB.
    The runtime role may access only checkpoint data and read migration history.
    """
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv('CHECKPOINT_DSN', '')
        self._manager: Any = None
        self._saver: Any = None
        self._lock = asyncio.Lock()
        self._mode: tuple[bool,bool] | None = None

    async def get(self) -> Any:
        validate_checkpoint_dsn(self.dsn)
        if os.getenv('CHECKPOINT_SETUP', 'false').strip().lower() == 'true':
            raise RuntimeError('Agent runtime forbids CHECKPOINT_SETUP; run the separate checkpoint bootstrap command')
        return await self._connect(setup=False, runtime=True)

    async def initialize_schema(self) -> Any:
        validate_checkpoint_dsn(self.dsn, runtime=False)
        return await self._connect(setup=True, runtime=False)

    async def _connect(self, *, setup: bool, runtime: bool) -> Any:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
        from psycopg.rows import tuple_row
        from .checkpoint_schema import checkpoint_schema_state
        from .checkpoint_privileges import validate_checkpoint_grants
        async with self._lock:
            if self._saver is not None:
                if self._mode != (setup,runtime):
                    raise RuntimeError('Checkpoint bootstrap and runtime connections cannot be shared; close before switching mode')
                return self._saver
            manager = AsyncPostgresSaver.from_conn_string(self.dsn)
            try:
                saver = await manager.__aenter__()
                self._manager = manager
                if setup:
                    async with saver.conn.cursor(row_factory=tuple_row) as cursor:
                        await cursor.execute('SELECT current_database()')
                        database = (await cursor.fetchone())[0]
                        digest = hashlib.sha256(('sdk-checkpoint:'+database).encode()).digest()
                        lock = int.from_bytes(digest[:8], 'big', signed=True)
                        await cursor.execute('SELECT pg_try_advisory_lock(%s)', (lock,))
                        if not (await cursor.fetchone())[0]:
                            raise RuntimeError('Checkpoint bootstrap is already running; retry after completion')
                        try:
                            state = await checkpoint_schema_state(saver.conn, 'public')
                            if state != 'ready':
                                await saver.setup()
                            if await checkpoint_schema_state(saver.conn, 'public') != 'ready':
                                raise RuntimeError('Checkpoint schema is not ready after initialization')
                        finally:
                            await cursor.execute('SELECT pg_advisory_unlock(%s)', (lock,))
                            if not (await cursor.fetchone())[0]:
                                raise RuntimeError('Checkpoint bootstrap lock release failed')
                elif await checkpoint_schema_state(saver.conn, 'public') != 'ready':
                    raise RuntimeError('Checkpoint schema requires the separate bootstrap command before runtime startup')
                if runtime:
                    await validate_checkpoint_grants(saver.conn)
                self._saver = saver
                self._mode = (setup,runtime)
                return saver
            except BaseException as error:
                await self._discard()
                if isinstance(error, (RuntimeError, asyncio.CancelledError)):
                    raise
                raise RuntimeError('PostgreSQL checkpoint connection or initialization failed') from None

    async def _discard(self) -> None:
        manager, self._manager, self._saver = self._manager, None, None
        self._mode = None
        if manager is not None:
            await manager.__aexit__(None, None, None)

    async def close(self) -> None:
        async with self._lock:
            await self._discard()


_default_provider = PostgresCheckpointProvider()

async def get_checkpointer() -> Any:
    return await _default_provider.get()

async def close_checkpointer() -> None:
    await _default_provider.close()

__all__ = ['PostgresCheckpointProvider', 'close_checkpointer', 'get_checkpointer', 'scoped_config']
