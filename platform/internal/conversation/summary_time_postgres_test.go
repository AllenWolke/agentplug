package conversation

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLConversationSummaryUsesPersistedUpdateTime(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("isolated database open failed")
	}
	defer db.Close()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("summary-time-%d", time.Now().UnixNano())
	scope := Scope{TenantID: id, DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "owner"}
	defer db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_conversation_session WHERE id=? AND tenant_id=?`), id, id)
	if err := store.CreateSession(ctx, scope, Session{Summary: Summary{ID: id, Kind: "qa", AgentID: "qa", AgentVersionID: "v1", InstallationID: "install", Title: "history", Status: "active"}}); err != nil {
		t.Fatal(err)
	}
	expected := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET updated_at=? WHERE id=? AND tenant_id=?`), expected, id, id); err != nil {
		t.Fatal(err)
	}
	check := func(item Summary) {
		t.Helper()
		if item.ID != id || item.UpdatedAt == nil || !item.UpdatedAt.Equal(expected) {
			t.Fatal("persisted history time missing", item)
		}
	}
	item, err := store.Detail(ctx, scope, id)
	if err != nil {
		t.Fatal(err)
	}
	check(item)
	page, err := store.List(ctx, scope, Query{Kind: "qa"})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("ordinary history read failed", err)
	}
	check(page.Items[0])
	page, err = store.SearchManaged(ctx, ManagedSearchQuery{TenantID: id, ApplicationID: "a", Kind: "qa"})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("managed history read failed", err)
	}
	check(page.Items[0])
	page, err = store.ListAuthorized(ctx, scope, Query{Kind: "qa"}, HistoryAccessPlan{Allow: []HistoryDataClause{{InstallationID: "install", Type: "owner"}}})
	if err != nil || len(page.Items) != 1 {
		t.Fatal("authorized history read failed", err)
	}
	check(page.Items[0])
	other := scope
	other.PrincipalID = "other"
	page, err = store.ListAuthorized(ctx, other, Query{Kind: "qa"}, HistoryAccessPlan{Allow: []HistoryDataClause{{InstallationID: "install", Type: "owner"}}})
	if err != nil || len(page.Items) != 0 {
		t.Fatal("other owner's history exposed", err)
	}
}
