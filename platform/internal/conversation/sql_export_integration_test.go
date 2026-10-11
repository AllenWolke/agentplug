package conversation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLConversationExportCompletenessAndRollback(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	unique := fmt.Sprintf("export-%d", time.Now().UnixNano())
	scope := Scope{TenantID: unique, DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "owner"}
	defer func() {
		for _, table := range []string{"platform_conversation_export", "platform_conversation_message", "platform_conversation_session"} {
			db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM `+table+` WHERE tenant_id=?`), unique)
		}
	}()
	seed := func(id string, count int, content string) {
		t.Helper()
		if err := store.CreateSession(ctx, scope, Session{Summary: Summary{ID: id, Kind: "qa", AgentID: "agent", AgentVersionID: "v1", Title: "export", Status: "active"}}); err != nil {
			t.Fatal(err)
		}
		for index := 0; index < count; index++ {
			_, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_message (id,session_id,tenant_id,department_id,application_id,principal_type,role,content,intent_code,knowledge_scope,metadata_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`), fmt.Sprintf("%s-%03d", id, index), id, unique, scope.DepartmentID, scope.ApplicationID, scope.PrincipalType, "user", content, "", "", `{}`, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	seed(unique, 305, "完整消息")
	foreign := scope
	foreign.PrincipalID = "foreign-owner"
	if _, err := store.CreateExport(ctx, foreign, ExportRequest{SessionIDs: []string{unique}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign owner export accepted: %v", err)
	}
	export, err := store.CreateExport(ctx, scope, ExportRequest{SessionIDs: []string{unique}})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Summary  Summary   `json:"summary"`
		Messages []Message `json:"messages"`
	}
	if err := json.Unmarshal([]byte(export.PayloadJSON), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Messages) != 305 || payload.Summary.MessageCount != 305 || payload.Messages[304].ID != unique+"-304" {
		t.Fatal("persisted export is incomplete")
	}
	oversized := unique + "-oversized"
	seed(oversized, 1, strings.Repeat("x", maxExportPayloadBytes))
	if _, err := store.CreateExport(ctx, scope, ExportRequest{SessionIDs: []string{oversized}}); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("oversized export did not fail explicitly: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_export WHERE session_id=?`), oversized).Scan(&count); err != nil || count != 0 {
		t.Fatalf("oversized export left a partial row: count=%d err=%v", count, err)
	}
}
