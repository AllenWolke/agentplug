"""Read-only structural/version checks for the pinned PostgreSQL saver."""
from typing import Any

REQUIRED_COLUMNS = {
 'checkpoint_migrations': {'v':'integer'},
 'checkpoints': {'thread_id':'text','checkpoint_ns':'text','checkpoint_id':'text','parent_checkpoint_id':'text','type':'text','checkpoint':'jsonb','metadata':'jsonb'},
 'checkpoint_blobs': {'thread_id':'text','checkpoint_ns':'text','channel':'text','version':'text','type':'text','blob':'bytea'},
 'checkpoint_writes': {'thread_id':'text','checkpoint_ns':'text','checkpoint_id':'text','task_id':'text','idx':'integer','channel':'text','type':'text','blob':'bytea','task_path':'text'},
}
REQUIRED_PRIMARY_KEYS = {
 'checkpoint_migrations':['v'],
 'checkpoints':['thread_id','checkpoint_ns','checkpoint_id'],
 'checkpoint_blobs':['thread_id','checkpoint_ns','channel','version'],
 'checkpoint_writes':['thread_id','checkpoint_ns','checkpoint_id','task_id','idx'],
}

def migration_state(versions: list[int], expected: int) -> str:
    # 不回退未来版本，也不通过重置历史来隐藏失败或缺失迁移。
    if any(type(version) is not int or version < 0 for version in versions):
        raise RuntimeError('Checkpoint migration history is invalid')
    ordered = sorted(versions)
    if ordered and ordered[-1] > expected:
        raise RuntimeError('Checkpoint schema is newer than this SDK; use a matching version or restore an approved backup')
    if ordered != list(range(len(ordered))):
        raise RuntimeError('Checkpoint migration history is incomplete; inspect or restore before deployment')
    return 'ready' if len(ordered) == expected + 1 else 'upgrade'


def _schema_queries(schema: str):
    """Shared validation, driven by either a synchronous or async cursor."""
    from langgraph.checkpoint.postgres import PostgresSaver
    if schema != 'public':
        raise RuntimeError('Checkpoint requires its dedicated public workflow schema')
    rows = yield ("SELECT c.relname,CASE WHEN c.relkind='r' THEN 'BASE TABLE' ELSE 'OTHER' END FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f')", (schema,))
    tables = {row[0]:row[1] for row in rows if row[0] in REQUIRED_COLUMNS}
    if 'checkpoint_migrations' not in tables:
        if tables:
            raise RuntimeError('Checkpoint tables exist without migration history; inspect or restore before deployment')
        return 'absent'
    if tables['checkpoint_migrations'] != 'BASE TABLE':
        raise RuntimeError('Checkpoint migration history must be a base table')
    rows = yield ('SELECT v FROM public.checkpoint_migrations ORDER BY v', ())
    state = migration_state([row[0] for row in rows], len(PostgresSaver.MIGRATIONS)-1)
    if state != 'ready':
        return state
    if set(tables) != set(REQUIRED_COLUMNS) or any(kind != 'BASE TABLE' for kind in tables.values()):
        raise RuntimeError('Checkpoint schema is incomplete despite completed migration history; inspect or restore before deployment')
    rows = yield ('SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema=%s', (schema,))
    columns = {(row[0],row[1]):row[2] for row in rows}
    for table,required in REQUIRED_COLUMNS.items():
        for name,kind in required.items():
            if columns.get((table,name)) != kind:
                raise RuntimeError('Checkpoint schema has missing or incompatible columns; inspect or restore before deployment')
    rows = yield ("SELECT c.relname,a.attname FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS key(attnum,position) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=key.attnum WHERE n.nspname=%s AND i.indisprimary ORDER BY c.relname,key.position", (schema,))
    keys={table:[] for table in REQUIRED_PRIMARY_KEYS}
    for table,name in rows:
        if table in keys: keys[table].append(name)
    if keys != REQUIRED_PRIMARY_KEYS:
        raise RuntimeError('Checkpoint primary keys are incompatible; inspect or restore before deployment')
    return 'ready'


def checkpoint_schema_state_sync(connection: Any, schema: str = 'public') -> str:
    from psycopg.rows import tuple_row
    queries = _schema_queries(schema)
    with connection.cursor(row_factory=tuple_row) as cursor:
        try:
            query, params = next(queries)
            while True:
                cursor.execute(query, params)
                query, params = queries.send(cursor.fetchall())
        except StopIteration as result:
            return result.value
        finally:
            queries.close()


async def checkpoint_schema_state(connection: Any, schema: str = 'public') -> str:
    from psycopg.rows import tuple_row
    queries = _schema_queries(schema)
    async with connection.cursor(row_factory=tuple_row) as cursor:
        try:
            query, params = next(queries)
            while True:
                await cursor.execute(query, params)
                query, params = queries.send(await cursor.fetchall())
        except StopIteration as result:
            return result.value
        finally:
            queries.close()
