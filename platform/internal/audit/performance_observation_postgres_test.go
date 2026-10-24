package audit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPerformanceObservationsAreImmutableScopedAndDMLOnly(t *testing.T) {
	migration, runtime := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if migration == "" || runtime == "" {
		t.Skip("owned PostgreSQL schema and DML role required")
	}
	for _, dsn := range []string{migration, runtime} {
		u, err := url.Parse(dsn)
		if err != nil || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/knowledge_test" {
			t.Fatal("dedicated registered fixture required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner, err := sqlutil.OpenPostgres(ctx, migration)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := NewSQLStore(owner).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	dml, err := sqlutil.OpenPostgres(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer dml.Close()
	s := NewSQLStore(dml)
	scope := performanceFixtureScope()
	scope.RunID = fmt.Sprintf("performance-fixture-%d", time.Now().UnixNano())
	o := performanceFixture(scope)
	for i := 0; i < 2; i++ {
		if err := s.RecordPerformance(ctx, scope, o); err != nil {
			t.Fatal(err)
		}
	}
	items, complete, err := s.ReadPerformanceObservations(ctx, scope)
	if err != nil || !complete || len(items) != 1 || items[0].DurationMS != 43 || *items[0].CacheHits != 3 {
		t.Fatal("measured exact replay failed", items, complete, err)
	}
	conflict := o
	conflict.FinishedAt = conflict.FinishedAt.Add(time.Millisecond)
	conflict.DurationMS++
	if err := s.RecordPerformance(ctx, scope, conflict); !errors.Is(err, ErrConflict) {
		t.Fatal("immutable observation was overwritten", err)
	}
	other := scope
	other.RunID += "-foreign"
	if items, complete, err := s.ReadPerformanceObservations(ctx, other); err != nil || !complete || len(items) != 0 {
		t.Fatal("observation crossed Run", items, complete, err)
	}
	other = scope
	other.PrincipalID += "-foreign"
	if _, _, err := s.ReadPerformanceObservations(ctx, other); err == nil {
		t.Fatal("same Run ID allowed foreign principal projection")
	}
	other = scope
	other.ApplicationID += "-foreign"
	if items, _, err := s.ReadPerformanceObservations(ctx, other); err != nil || len(items) != 0 {
		t.Fatal("observation crossed application", items, err)
	}
	if _, err := dml.ExecContext(ctx, `CREATE TABLE performance_unauthorized_ddl (id int)`); err == nil {
		t.Fatal("performance reader/writer has unexpected DDL permissions")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_audit_event SET summary=? WHERE event_id=?`), `{"prompt":"PRIVATE PAYLOAD"}`, o.StepID); err != nil {
		t.Fatal(err)
	}
	if items, _, err := s.ReadPerformanceObservations(ctx, scope); err == nil || len(items) != 0 {
		t.Fatal("corrupt/private audit data reached public projection")
	}
}
