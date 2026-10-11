package main

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

const devRuntimeUser = "platform_runtime"

var runtimePasswordPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)

// Only dedicated local development instances provision this fixed role. A
// cluster-wide transaction lock serializes creation. The provenance comment
// prevents reuse in another database. Passwords and unrelated grants never change;
// explicit upgrades restrict only newly installed owner metadata in one transaction.
// Production operators provision migration/runtime roles independently.
func provisionDevRuntimeAccount(ctx context.Context, db *sql.DB, environment, dsn, password string) error {
	if environment != "development" || !runtimePasswordPattern.MatchString(password) {
		return errors.New("development runtime account requires APP_ENV=development and a 24-128 character URL-safe password")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || strings.TrimSpace(dsn) == "" || cfg.Database == "" || db == nil {
		return errors.New("development runtime account requires a selected PostgreSQL database")
	}
	var database string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil || database != cfg.Database {
		return errors.New("development runtime account database mismatch")
	}
	cfg.User, cfg.Password = devRuntimeUser, password
	runtime := stdlib.OpenDB(*cfg)
	defer runtime.Close()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("development runtime account transaction unavailable")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout='10s'`); err != nil {
		return errors.New("development runtime role lock configuration failed")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(731320261002)`); err != nil {
		return errors.New("development runtime role lock unavailable")
	}
	var provenance sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT shobj_description(oid,'pg_authid') FROM pg_catalog.pg_roles WHERE rolname='platform_runtime'`).Scan(&provenance)
	expected := "agentplug-development-runtime:" + database
	if err == nil {
		if !provenance.Valid || provenance.String != expected || runtime.PingContext(ctx) != nil {
			return errors.New("development runtime account credentials or database scope conflict; existing credentials were not replaced")
		}
		// Default DML grants from an earlier bundle can reach new metadata.
		// Only the authenticated, provenance-bound local role is narrowed.
		// All unrelated role/schema drift still fails and rolls back this change.
		for _, statement := range runtimeOwnerMetadataRestrictions {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return errors.New("development runtime metadata upgrade failed; transaction rolled back")
			}
		}
		if err := checkDevRuntimeTransaction(ctx, tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return errors.New("development runtime role lookup failed")
	}
	identifier := pgx.Identifier{database}.Sanitize()
	literal := strings.ReplaceAll(expected, "'", "''")
	statements := []string{
		`SET LOCAL standard_conforming_strings=on`,
		`CREATE ROLE platform_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '` + password + `'`,
		`COMMENT ON ROLE platform_runtime IS '` + literal + `'`,
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`REVOKE TEMP ON DATABASE ` + identifier + ` FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE ` + identifier + ` TO platform_runtime`,
		`GRANT USAGE ON SCHEMA public,knowledge TO platform_runtime`,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public,knowledge TO platform_runtime`,
		`REVOKE INSERT,UPDATE,DELETE ON platform_schema_version FROM platform_runtime`,
		`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public,knowledge TO platform_runtime`,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public,knowledge GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO platform_runtime`,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public,knowledge GRANT USAGE,SELECT ON SEQUENCES TO platform_runtime`,
	}
	for _, statement := range append(statements, runtimeOwnerMetadataRestrictions...) {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return errors.New("development runtime role provisioning failed; transaction rolled back")
		}
	}
	if err := checkDevRuntimeTransaction(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("development runtime role commit failed")
	}
	if runtime.PingContext(ctx) != nil || schemaversion.CheckRuntimePrivileges(ctx, runtime) != nil {
		return errors.New("development runtime account verification unavailable")
	}
	return nil
}

// These platform-owned tables are installed by the complete explicit bundle.
// Do not grant DDL, repair PUBLIC/schema privileges, rotate credentials, or
// broaden unrelated business grants while replaying a development upgrade.
var runtimeOwnerMetadataRestrictions = []string{
	`REVOKE INSERT,UPDATE,DELETE ON platform_compensation_schema_version FROM platform_runtime`,
	`REVOKE UPDATE,DELETE ON platform_compensation_event FROM platform_runtime`,
	`REVOKE DELETE ON platform_compensation_step,platform_cancellation_operation FROM platform_runtime`,
	`REVOKE DELETE ON platform_compensation_local_effect FROM platform_runtime`,
	`REVOKE UPDATE,DELETE ON platform_cancellation_effect FROM platform_runtime`,
	`REVOKE INSERT,UPDATE,DELETE ON platform_notification_control_version FROM platform_runtime`,
	`REVOKE DELETE ON platform_notification_inbox FROM platform_runtime`,
	`REVOKE INSERT,UPDATE,DELETE ON platform_kafka_dead_letter_schema_version FROM platform_runtime`,
	`REVOKE UPDATE,DELETE ON platform_kafka_dead_letter_action FROM platform_runtime`,
	`REVOKE DELETE ON platform_kafka_dead_letter FROM platform_runtime`,
}

func checkDevRuntimeTransaction(ctx context.Context, tx *sql.Tx) error {
	// The effective-privilege check must see uncommitted restrictions as the
	// original runtime identity. Commit/rollback restores the migration session.
	if _, err := tx.ExecContext(ctx, `SET LOCAL SESSION AUTHORIZATION platform_runtime`); err != nil {
		return errors.New("development runtime identity verification unavailable")
	}
	facade := sqlutil.TransactionDB(tx)
	defer facade.Close()
	if err := schemaversion.CheckRuntimePrivileges(ctx, facade); err != nil {
		return errors.New("development runtime role effective grants unsafe; transaction rolled back")
	}
	return nil
}
