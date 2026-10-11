package catalog

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLInstallationTargetPagesBeyondOneHundred(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.Contains(config.Database, "test") && !strings.Contains(config.Database, "fixture") {
		t.Fatal("installation pagination requires an isolated test database")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := NewSQLStore(db, "pgx")
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("catalog-page-fixture-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_catalog_installation_options WHERE installation_id IN (SELECT id FROM platform_catalog_installation WHERE tenant_id=?)`), tenant); err != nil {
			t.Error(err)
		}
		if _, err := db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_catalog_installation WHERE tenant_id=?`), tenant); err != nil {
			t.Error(err)
		}
	})
	for i := 0; i < 115; i++ {
		app := "app"
		if i >= 113 {
			app = "outside-app"
		}
		id := fmt.Sprintf("%s-%03d", tenant, i)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_installation(id,tenant_id,department_id,application_id,agent_id,version_id,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,'active',1,clock_timestamp(),clock_timestamp())`), id, tenant, "dept", app, fmt.Sprintf("agent-%03d", i), "fixture-version"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_catalog_installation_options(installation_id,display_name,deployment_mode,drain_policy,retention_policy_id,created_at) VALUES(?,?,'managed','wait','fixture-retention',clock_timestamp())`), id, "Agent "+id); err != nil {
			t.Fatal(err)
		}
	}
	items, cursor, err := s.PageInstallationTargets(ctx, tenant, "dept", "app", "", 100)
	if err != nil || len(items) != 100 || cursor != items[99].ID {
		t.Fatal("first page missing stable continuation", err)
	}
	remaining, next, err := s.PageInstallationTargets(ctx, tenant, "dept", "app", cursor, 100)
	if err != nil || len(remaining) != 13 || next != "" || remaining[0].ID <= cursor {
		t.Fatal("Agent 101 cannot be selected or scope widened", len(remaining), err)
	}
	for _, item := range remaining {
		if item.ApplicationID != "app" || item.TenantID != tenant || item.DepartmentID != "dept" {
			t.Fatal("cursor escaped authorized application")
		}
	}
	if items, _, err := s.PageInstallationTargets(ctx, tenant, "another-dept", "app", "", 100); err != nil || len(items) != 0 {
		t.Fatal("department boundary lost", err)
	}
	if _, _, err := s.PageInstallationTargets(ctx, tenant, "dept", "app", "", 101); err == nil {
		t.Fatal("unbounded page size accepted")
	}
	if _, _, err := s.PageInstallationTargets(ctx, tenant, "dept", "", "", 100); err == nil {
		t.Fatal("unscoped cursor accepted")
	}
}
