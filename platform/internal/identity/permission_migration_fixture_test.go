package identity

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Migration rollback assertions require an empty private database, including
// audit/outbox tables. Other packages may run against the supplied fixture.
func newEmptyMigrationFixture(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated migration fixture DSN")
	}
	if config.Host != "127.0.0.1" || config.Database != "knowledge_test" || config.User != "postgres" {
		t.Fatal("migration test requires dedicated loopback PostgreSQL fixture")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		control.Close()
		t.Fatal(err)
	}
	name := fmt.Sprintf("permission_migration_fixture_%x", suffix)
	if _, err := control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		control.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
		control.Close()
	})
	config.Database = name
	db := stdlib.OpenDB(*config)
	err = db.PingContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
