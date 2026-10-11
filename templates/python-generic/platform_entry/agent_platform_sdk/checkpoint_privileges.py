"""Read-only effective PostgreSQL permission validation for workflow runtimes."""
from typing import Any

QUERY = """SELECT
 current_user = session_user AND current_schema()='public'
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
  AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=current_user)
 AND NOT has_database_privilege(current_database(),'CREATE,TEMP,CONNECT WITH GRANT OPTION')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND (n.nspowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
   OR has_schema_privilege(n.oid,'CREATE,USAGE WITH GRANT OPTION')
   OR (n.nspname <> 'public' AND has_schema_privilege(n.oid,'USAGE'))))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND (c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
   OR (c.relkind IN ('r','p','v','m','f') AND (
    has_table_privilege(c.oid,'TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION')
    OR ((n.nspname <> 'public' OR c.relname NOT IN ('checkpoint_migrations','checkpoints','checkpoint_blobs','checkpoint_writes','sdk_execution_generation')) AND has_table_privilege(c.oid,'SELECT,INSERT,UPDATE,DELETE'))))
   OR (c.relkind='S' AND has_sequence_privilege(c.oid,'UPDATE,USAGE WITH GRANT OPTION,SELECT WITH GRANT OPTION'))))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND p.prosecdef AND has_function_privilege(p.oid,'EXECUTE'))

 AND (to_regclass('public.sdk_execution_generation') IS NULL
  OR NOT has_table_privilege(to_regclass('public.sdk_execution_generation'),'DELETE')) AND has_table_privilege(to_regclass('public.checkpoint_migrations'),'SELECT')
 AND NOT has_table_privilege(to_regclass('public.checkpoint_migrations'),'INSERT,UPDATE,DELETE')
 AND (SELECT COUNT(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('checkpoints','checkpoint_blobs','checkpoint_writes')
 AND has_table_privilege(c.oid,'SELECT') AND has_table_privilege(c.oid,'INSERT')
 AND has_table_privilege(c.oid,'UPDATE') AND has_table_privilege(c.oid,'DELETE'))=3
"""

async def validate_checkpoint_grants(connection: Any) -> None:
    from psycopg.rows import tuple_row
    async with connection.cursor(row_factory=tuple_row) as cursor:
        await cursor.execute(QUERY)
        row = await cursor.fetchone()
    if not row or row[0] is not True:
        raise RuntimeError('Checkpoint runtime requires DML-only privileges on workflow tables and read-only migration history')
