package audit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

func TestSQLAuditMetadataScopeIsolationAndPagination(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}

	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" || (uri.Scheme != "postgres" && uri.Scheme != "postgresql") {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	name := fmt.Sprintf("audit_metadata_%d", time.Now().UnixNano())
	if _, err = control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	dsn = uri.String()
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := NewSQLStore(db)
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, coords := range [][3]string{{"t", "d", "a"}, {"t", "d", "b"}, {"t", "other", "c"}, {"foreign", "d", "a"}} {
		event := Event{ID: fmt.Sprintf("event-%d", i), TenantID: coords[0], DepartmentID: coords[1], ApplicationID: coords[2], ActorID: "fixture", AggregateType: "run", AggregateID: "task", TraceID: "trace", Action: "run.completed", Outcome: "success", Summary: "sensitive fixture text", CreatedAt: now.Add(time.Duration(i) * time.Second)}
		if err := s.Record(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		scope MetadataScope
		total int64
	}{
		{MetadataScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}, 1},
		{MetadataScope{Type: "department", TenantID: "t", DepartmentID: "d"}, 2},
		{MetadataScope{Type: "tenant", TenantID: "t"}, 3},
		{MetadataScope{Type: "global"}, 4},
	} {
		for page := 1; page <= int(tc.total); page++ {
			result, err := s.ListMetadata(ctx, MetadataQuery{Scope: tc.scope, Page: page, PageSize: 1, TaskID: "task"})
			if err != nil || result.Total != tc.total || len(result.Items) != 1 || result.Page != page || !result.MetadataOnly {
				t.Fatalf("scope=%v page=%d result=%v error=%v", tc.scope, page, result, err)
			}
			if !tc.scope.contains(result.Items[0]) || result.Items[0].Summary != "" {
				t.Fatal("metadata returned forbidden scope or content")
			}
		}
	}
	missing, err := s.ListMetadata(ctx, MetadataQuery{Scope: MetadataScope{Type: "global"}, TraceID: "missing"})
	if err != nil || missing.Total != 0 || len(missing.Items) != 0 {
		t.Fatal("trace filter leaked records", err)
	}
	for _, invalid := range []MetadataQuery{{Scope: MetadataScope{Type: "global", TenantID: "t"}}, {Scope: MetadataScope{Type: "application"}}, {Scope: MetadataScope{Type: "global"}, Page: math.MaxInt, PageSize: 100}} {
		if _, err := s.ListMetadata(ctx, invalid); !errors.Is(err, ErrInvalidEvent) {
			t.Fatal("malformed metadata query allowed", err)
		}
	}
	var summary string
	appScope := MetadataScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	header, err := s.GetEventMetadata(ctx, appScope, "event-0")
	if err != nil || header.ID != "event-0" || header.Summary != "" {
		t.Fatal("content metadata lookup exposed summary", header, err)
	}
	body, err := s.GetEventContent(ctx, header)
	if err != nil || body.Summary != "sensitive fixture text" {
		t.Fatal("authorized content lookup failed", err)
	}
	if _, err := s.GetEventMetadata(ctx, appScope, "event-3"); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant event metadata was returned", err)
	}
	wrong := header
	wrong.AggregateID = "wrong-run"
	if _, err := s.GetEventContent(ctx, wrong); !errors.Is(err, ErrNotFound) {
		t.Fatal("body lookup ignored authoritative aggregate", err)
	}
	if _, err := s.GetEventContent(ctx, body); !errors.Is(err, ErrInvalidEvent) {
		t.Fatal("content-bearing header accepted", err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT summary FROM platform_audit_event WHERE event_id='event-0'`)).Scan(&summary); err != nil || summary != "sensitive fixture text" {
		t.Fatal("metadata read overwrote historical evidence", err)
	}
}
