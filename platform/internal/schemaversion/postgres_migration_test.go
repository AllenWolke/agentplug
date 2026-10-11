package schemaversion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/sqlutil"
)

func postgresSchemaFixture(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	admin, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := fmt.Sprintf("pg_schema_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	})
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = name
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPostgresSchemaConcurrentMigrationAndDrift(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	if !errors.Is(Check(ctx, db), ErrIncompatible) {
		t.Fatal("missing schema admitted")
	}
	var calls atomic.Int32
	bundle := func(ctx context.Context, db *sql.DB) error {
		calls.Add(1)
		if _, err := db.ExecContext(ctx, `CREATE TABLE fixture_data(id INT PRIMARY KEY)`); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, `INSERT INTO fixture_data(id) VALUES(1)`)
		return err
	}
	var workers sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); results <- ApplyPostgres(ctx, db, bundle) }()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("bundle calls=%d", calls.Load())
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE platform_schema_version SET checksum='drifted'`); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(ApplyPostgres(ctx, db, bundle), ErrIncompatible) || !errors.Is(Check(ctx, db), ErrIncompatible) {
		t.Fatal("drift accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("drift reran bundle")
	}
	if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET version=?,checksum=?`), CurrentVersion+1, CurrentChecksum()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(ApplyPostgres(ctx, db, bundle), ErrIncompatible) || !errors.Is(Check(ctx, db), ErrIncompatible) || calls.Load() != 1 {
		t.Fatal("future schema accepted or migration rerun")
	}

}

func TestPostgresSchemaBundleRollbackAndRetry(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	fault := errors.New("injected migration failure")
	err := ApplyPostgres(ctx, db, func(ctx context.Context, facade *sql.DB) error {
		if _, err := facade.ExecContext(ctx, `CREATE TABLE fixture_rollback(id INT PRIMARY KEY)`); err != nil {
			return err
		}
		if _, err := facade.ExecContext(ctx, `INSERT INTO fixture_rollback(id) VALUES(1)`); err != nil {
			return err
		}
		var count int
		if err := facade.QueryRowContext(ctx, `SELECT COUNT(*) FROM fixture_rollback`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("transaction facade read=%d err=%v", count, err)
		}
		if _, err := facade.BeginTx(ctx, nil); err == nil {
			t.Fatal("nested transaction admitted")
		}
		return fault
	})
	if !errors.Is(err, fault) {
		t.Fatal(err)
	}
	for _, name := range []string{"fixture_rollback", "platform_schema_version"} {
		var absent bool
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT to_regclass(?) IS NULL`), name).Scan(&absent); err != nil || !absent {
			t.Fatalf("partial DDL remained: %s %v", name, err)
		}
	}
	if err := ApplyPostgres(ctx, db, func(ctx context.Context, db *sql.DB) error {
		_, err := db.ExecContext(ctx, `CREATE TABLE fixture_rollback(id INT PRIMARY KEY)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSchemaRejectsLegacyLineage(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE platform_schema_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64),applied_at TIMESTAMPTZ)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(sqlutil.Bind(`INSERT INTO platform_schema_version VALUES(?,?,clock_timestamp())`), LegacyVersion, LegacyChecksum()); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := ApplyPostgres(ctx, db, func(context.Context, *sql.DB) error { called = true; return nil }); !errors.Is(err, ErrIncompatible) || called {
		t.Fatalf("legacy lineage adopted: called=%t err=%v", called, err)
	}
}

func TestPostgresSchemaNativePredecessorUpgrade(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE platform_schema_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64),applied_at TIMESTAMPTZ); CREATE TABLE upgrade_fixture(id INT PRIMARY KEY); INSERT INTO upgrade_fixture VALUES(7)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(sqlutil.Bind(`INSERT INTO platform_schema_version VALUES(?,?,clock_timestamp())`), PostgresInitialVersion, "drifted"); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	bundle := func(ctx context.Context, facade *sql.DB) error {
		calls.Add(1)
		_, err := facade.ExecContext(ctx, `CREATE INDEX upgrade_fixture_lookup ON upgrade_fixture(id)`)
		return err
	}
	if !errors.Is(ApplyPostgres(ctx, db, bundle), ErrIncompatible) || calls.Load() != 0 {
		t.Fatal("native predecessor drift accepted")
	}
	if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_schema_version SET checksum=?`), PostgresInitialChecksum()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Check(ctx, db), ErrIncompatible) {
		t.Fatal("old runtime version admitted before explicit migration")
	}
	fault := errors.New("native upgrade rollback")
	if err := ApplyPostgres(ctx, db, func(ctx context.Context, facade *sql.DB) error {
		if _, err := facade.ExecContext(ctx, `CREATE INDEX upgrade_fixture_lookup ON upgrade_fixture(id)`); err != nil {
			return err
		}
		return fault
	}); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	var indexPresent bool
	if err := db.QueryRow(`SELECT to_regclass('upgrade_fixture_lookup') IS NOT NULL`).Scan(&indexPresent); err != nil || indexPresent {
		t.Fatal("failed native upgrade left index", err)
	}
	var markers int
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_schema_version`).Scan(&markers); err != nil || markers != 1 {
		t.Fatal("failed upgrade changed markers", err)
	}
	var workers sync.WaitGroup
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); results <- ApplyPostgres(ctx, db, bundle) }()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("upgrade executed more than once", calls.Load())
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM platform_schema_version`).Scan(&markers); err != nil || markers != 2 {
		t.Fatal("native predecessor marker not preserved", err)
	}
	var id int
	if err := db.QueryRow(`SELECT id FROM upgrade_fixture`).Scan(&id); err != nil || id != 7 {
		t.Fatal("upgrade changed existing data", err)
	}
	if err := ApplyPostgres(ctx, db, bundle); err != nil || calls.Load() != 1 {
		t.Fatal("upgrade replay reran bundle", err)
	}
}

func TestPostgresDelegationAuthorityMarkerUpgradesFromModelUsageStep(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE platform_schema_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64),applied_at TIMESTAMPTZ)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(sqlutil.Bind(`INSERT INTO platform_schema_version VALUES(?,?,clock_timestamp())`), ModelUsageStepVersion, ModelUsageStepChecksum()); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	bundle := func(ctx context.Context, facade *sql.DB) error {
		calls.Add(1)
		_, err := facade.ExecContext(ctx, `CREATE TABLE permission_catalog_v2_upgrade_fixture(id INT PRIMARY KEY)`)
		return err
	}
	if err := ApplyPostgres(ctx, db, bundle); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("migration callback calls=%d", calls.Load())
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	var markers int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_schema_version`).Scan(&markers); err != nil || markers != 2 {
		t.Fatalf("expected to preserve 0409 and append current marker: markers=%d err=%v", markers, err)
	}
	if err := ApplyPostgres(ctx, db, bundle); err != nil || calls.Load() != 1 {
		t.Fatalf("current marker reran the migration callback: calls=%d err=%v", calls.Load(), err)
	}
}

func TestPostgresDelegationAuthorityMarkerUpgradesFromPermissionCatalogV2(t *testing.T) {
	db := postgresSchemaFixture(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE platform_schema_version(version BIGINT PRIMARY KEY,checksum VARCHAR(64),applied_at TIMESTAMPTZ);
CREATE TABLE platform_agent_child_reservation(child_key VARCHAR(64) PRIMARY KEY);
INSERT INTO platform_agent_child_reservation(child_key) VALUES('existing-child');`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(sqlutil.Bind(`INSERT INTO platform_schema_version VALUES(?,?,clock_timestamp())`), PermissionCatalogV2Version, PermissionCatalogV2Checksum()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Check(ctx, db), ErrIncompatible) {
		t.Fatal("pre-upgrade schema marker admitted by runtime")
	}
	var calls atomic.Int32
	bundle := func(ctx context.Context, facade *sql.DB) error {
		calls.Add(1)
		routes, err := agentcoordination.NewSQLRouteStore(facade)
		if err != nil {
			return err
		}
		return routes.EnsureDelegationAuthoritySchema(ctx)
	}
	if err := ApplyPostgres(ctx, db, bundle); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("migration callback calls=%d", calls.Load())
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	var columnPresent, tablePresent bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='platform_agent_child_reservation' AND column_name='delegation_authority_json')`).Scan(&columnPresent); err != nil || !columnPresent {
		t.Fatalf("delegation proof column missing after upgrade: present=%t err=%v", columnPresent, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('platform_agent_delegation_root_authority') IS NOT NULL`).Scan(&tablePresent); err != nil || !tablePresent {
		t.Fatalf("root authority table missing after upgrade: present=%t err=%v", tablePresent, err)
	}
	var childKey string
	var proof sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT child_key,delegation_authority_json FROM platform_agent_child_reservation`).Scan(&childKey, &proof); err != nil || childKey != "existing-child" || proof.Valid {
		t.Fatalf("upgrade did not preserve old reservation fail-closed: child=%q proof=%v err=%v", childKey, proof, err)
	}
	var markers int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_schema_version`).Scan(&markers); err != nil || markers != 2 {
		t.Fatalf("expected to preserve 0501 and append current marker: markers=%d err=%v", markers, err)
	}
	var oldChecksum, newChecksum string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_schema_version WHERE version=?`), PermissionCatalogV2Version).Scan(&oldChecksum); err != nil || oldChecksum != PermissionCatalogV2Checksum() {
		t.Fatalf("old manifest marker changed: checksum=%q err=%v", oldChecksum, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT checksum FROM platform_schema_version WHERE version=?`), CurrentVersion).Scan(&newChecksum); err != nil || newChecksum != CurrentChecksum() {
		t.Fatalf("new manifest marker mismatch: checksum=%q err=%v", newChecksum, err)
	}
	if err := ApplyPostgres(ctx, db, bundle); err != nil || calls.Load() != 1 {
		t.Fatalf("migration replay reran the callback: calls=%d err=%v", calls.Load(), err)
	}
}
