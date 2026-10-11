package schemaversion

import (
	"context"
	"database/sql"
	"errors"
)

var ErrRuntimePrivileges = errors.New("runtime PostgreSQL account must have only scoped DML privileges; use a separate migration account")

// CheckRuntimePrivileges inspects effective PostgreSQL permissions, including
// PUBLIC grants. It never changes grants or logs credentials/catalog contents.
// Runtime connections cannot switch roles or own schema objects. Sequence USAGE
// is allowed for identity inserts; UPDATE/setval, DDL and grant options are not.
func CheckRuntimePrivileges(ctx context.Context, db *sql.DB) error {
	var safe bool
	if db == nil || db.QueryRowContext(ctx, runtimePrivilegeQuery).Scan(&safe) != nil || !safe {
		return ErrRuntimePrivileges
	}
	return nil
}

const runtimePrivilegeQuery = `SELECT
 current_user = session_user
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
  AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=current_user)
 AND NOT has_database_privilege(current_database(),'CREATE,TEMP,CONNECT WITH GRANT OPTION')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND (n.nspowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
   OR has_schema_privilege(n.oid,'CREATE,USAGE WITH GRANT OPTION')
   OR (n.nspname NOT IN ('public','knowledge') AND has_schema_privilege(n.oid,'USAGE'))))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND (c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
   OR (c.relkind IN ('r','p','v','m','f') AND (
    has_table_privilege(c.oid,'TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION')
    OR (n.nspname NOT IN ('public','knowledge') AND has_table_privilege(c.oid,'SELECT,INSERT,UPDATE,DELETE'))))
   OR (c.relkind='S' AND has_sequence_privilege(c.oid,'UPDATE,USAGE WITH GRANT OPTION,SELECT WITH GRANT OPTION'))))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
  AND p.prosecdef AND has_function_privilege(p.oid,'EXECUTE'))
 AND has_table_privilege(to_regclass('public.platform_schema_version'),'SELECT')
 AND NOT has_table_privilege(to_regclass('public.platform_schema_version'),'INSERT,UPDATE,DELETE')
 AND (to_regclass('public.platform_compensation_schema_version') IS NULL OR
  (has_table_privilege(to_regclass('public.platform_compensation_schema_version'),'SELECT')
   AND NOT has_table_privilege(to_regclass('public.platform_compensation_schema_version'),'INSERT,UPDATE,DELETE')))
 AND (to_regclass('public.platform_compensation_event') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_compensation_event'),'UPDATE,DELETE'))
 AND (to_regclass('public.platform_compensation_step') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_compensation_step'),'DELETE'))
 AND (to_regclass('public.platform_compensation_local_effect') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_compensation_local_effect'),'DELETE'))
 AND (to_regclass('public.platform_cancellation_effect') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_cancellation_effect'),'UPDATE,DELETE'))
 AND (to_regclass('public.platform_notification_control_version') IS NULL OR
  (has_table_privilege(to_regclass('public.platform_notification_control_version'),'SELECT')
   AND NOT has_table_privilege(to_regclass('public.platform_notification_control_version'),'INSERT,UPDATE,DELETE')))
 AND (to_regclass('public.platform_notification_inbox') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_notification_inbox'),'DELETE'))
 AND (to_regclass('public.platform_kafka_dead_letter_schema_version') IS NULL OR
  (has_table_privilege(to_regclass('public.platform_kafka_dead_letter_schema_version'),'SELECT')
   AND NOT has_table_privilege(to_regclass('public.platform_kafka_dead_letter_schema_version'),'INSERT,UPDATE,DELETE')))
 AND (to_regclass('public.platform_kafka_dead_letter_action') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_kafka_dead_letter_action'),'UPDATE,DELETE'))
 AND (to_regclass('public.platform_kafka_dead_letter') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_kafka_dead_letter'),'DELETE'))
 AND (to_regclass('public.platform_cancellation_operation') IS NULL OR
  NOT has_table_privilege(to_regclass('public.platform_cancellation_operation'),'DELETE'))`
