"""SDK-owned PostgreSQL checkpoints for synchronous Graph/HTTP workers."""
from __future__ import annotations

import os
import threading
from typing import Any

from .checkpoint import validate_checkpoint_dsn
from .checkpoint_schema import checkpoint_schema_state_sync
from .checkpoint_privileges import QUERY


class SyncPostgresCheckpointProvider:
    """Runtime-only provider. Apply migrations with checkpoint_bootstrap first."""

    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or os.getenv('CHECKPOINT_DSN', '')
        self._manager: Any = None
        self._saver: Any = None
        self._lock = threading.RLock()

    def get(self) -> Any:
        validate_checkpoint_dsn(self.dsn)
        if os.getenv('CHECKPOINT_SETUP', '').strip().lower() in {'1', 'true', 'yes'}:
            raise RuntimeError('Checkpoint runtime must not apply schema migrations; use checkpoint_bootstrap')
        with self._lock:
            if self._saver is not None:
                return self._saver
            try:
                from langgraph.checkpoint.postgres import PostgresSaver
                from psycopg.rows import tuple_row
                self._manager = PostgresSaver.from_conn_string(self.dsn)
                saver = self._manager.__enter__()
                if checkpoint_schema_state_sync(saver.conn) != 'ready':
                    raise RuntimeError('Checkpoint schema is not initialized; use checkpoint_bootstrap')
                with saver.conn.cursor(row_factory=tuple_row) as cursor:
                    cursor.execute(QUERY)
                    row = cursor.fetchone()
                if not row or row[0] is not True:
                    raise RuntimeError('Checkpoint runtime requires DML-only privileges on workflow tables and read-only migration history')
                self._saver = saver
                return saver
            except BaseException as error:
                self.close()
                if isinstance(error, (RuntimeError, KeyboardInterrupt, SystemExit)):
                    raise
                raise RuntimeError('PostgreSQL checkpoint connection or validation failed') from None

    def close(self) -> None:
        with self._lock:
            manager, self._manager = self._manager, None
            self._saver = None
            if manager is not None:
                manager.__exit__(None, None, None)

    def __enter__(self) -> Any:
        return self.get()

    def __exit__(self, *exc: Any) -> None:
        self.close()
