package compensation

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestPostgresCompensationMigrationProtectsHistoryACL(t *testing.T) {
	ctx, db, _, _, root := ownedFixture(t)
	role := "compensation_acl_" + root.RunID[4:]
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := db.ExecContext(ctx, "CREATE ROLE "+quoted+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP OWNED BY "+quoted)
		_, _ = db.ExecContext(context.Background(), "DROP ROLE "+quoted)
	})
	tables := []string{"platform_compensation_schema_version", "platform_cancellation_operation", "platform_compensation_step", "platform_compensation_event"}
	for _, name := range tables {
		if _, err := db.ExecContext(ctx, "GRANT SELECT,INSERT,UPDATE,DELETE ON "+pgx.Identifier{name}.Sanitize()+" TO "+quoted); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		table, permission string
		want              bool
	}{
		{"platform_compensation_schema_version", "SELECT", true},
		{"platform_compensation_schema_version", "INSERT,UPDATE,DELETE", false},
		{"platform_cancellation_operation", "SELECT,INSERT,UPDATE", true},
		{"platform_cancellation_operation", "DELETE", false},
		{"platform_compensation_step", "SELECT,INSERT,UPDATE", true},
		{"platform_compensation_step", "DELETE", false},
		{"platform_compensation_event", "SELECT,INSERT", true},
		{"platform_compensation_event", "UPDATE,DELETE", false},
	}
	for _, check := range checks {
		var got bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT has_table_privilege(?,?,?)`), role, check.table, check.permission).Scan(&got); err != nil || got != check.want {
			t.Fatalf("history permission %s/%s: got=%t want=%t error=%v", check.table, check.permission, got, check.want, err)
		}
	}
}

func TestPostgresCompensationMigrationDriftRollsBackOuterBundle(t *testing.T) {
	ctx, db, _, _, root := ownedFixture(t)
	var before string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), SchemaVersion).Scan(&before); err != nil {
		t.Fatal(err)
	}
	probe := "compensation_bundle_probe_" + root.RunID[4:]
	err := runTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "CREATE TABLE "+pgx.Identifier{probe}.Sanitize()+"(id BIGINT)"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_compensation_schema_version SET checksum=? WHERE version=?`), "0000000000000000000000000000000000000000000000000000000000000000", SchemaVersion); err != nil {
			return err
		}
		facade := sqlutil.TransactionDB(tx)
		defer facade.Close()
		return ApplySchema(ctx, facade)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("changed version must reject the outer bundle: %v", err)
	}
	var after string
	var exists bool
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_compensation_schema_version WHERE version=?`), SchemaVersion).Scan(&after); err != nil || before != after {
		t.Fatalf("failed bundle changed released marker: %v", err)
	}
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT to_regclass(?) IS NOT NULL`), "public."+probe).Scan(&exists); err != nil || exists {
		t.Fatalf("failed migration committed preceding DDL: %v", err)
	}
}
