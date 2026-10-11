package conversation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// A reused session ID must not merge the output of another installation,
// even when the human owner and published Agent version are identical.
func TestSQLConversationInstallationProvenance(t *testing.T) {
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
	id := fmt.Sprintf("provenance-%d", time.Now().UnixNano())
	scope := Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", PrincipalType: "user", PrincipalID: "owner"}
	run := sharedkernel.Scope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", PrincipalType: "user", PrincipalID: "owner", SessionID: id, RunID: id, AgentID: "qa", AgentVersionID: "v1", InstallationID: "installation-a"}
	request := []byte(`{"input":{"question":"installation provenance","intent_hint":"AUTHORITY_QUERY","knowledge_scope":"fixture-knowledge"}}`)
	if err := store.RecordRun(ctx, run, request); err != nil {
		t.Fatal(err)
	}
	var intent, knowledge string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT intent_code,knowledge_scope FROM platform_conversation_message WHERE session_id=? AND tenant_id=? AND role='user'`), id, id).Scan(&intent, &knowledge); err != nil || intent != "AUTHORITY_QUERY" || knowledge != "fixture-knowledge" {
		t.Fatal("runtime projection lost question metadata", intent, knowledge, err)
	}
	if err := store.RecordRunResult(ctx, run, id, map[string]any{"answer": "answer a"}); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct {
		name  string
		apply func(*sharedkernel.Scope)
	}{
		{"installation", func(s *sharedkernel.Scope) { s.InstallationID = "installation-b" }},
		{"missing installation", func(s *sharedkernel.Scope) { s.InstallationID = "" }},
		{"agent", func(s *sharedkernel.Scope) { s.AgentID = "foreign-agent" }},
		{"version", func(s *sharedkernel.Scope) { s.AgentVersionID = "v2" }},
		{"owner", func(s *sharedkernel.Scope) { s.PrincipalID = "foreign-owner" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			foreign := run
			mutation.apply(&foreign)
			if err := store.RecordRun(ctx, foreign, request); err == nil {
				t.Fatal("foreign run accepted")
			}
			if err := store.RecordRunResult(ctx, foreign, id, map[string]any{"answer": "answer a"}); err == nil {
				t.Fatal("foreign result replay accepted")
			}
		})
	}
	// A v2 run cannot silently adopt an old session whose installation has
	// not yet been established by the historical migration.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET installation_id='' WHERE id=? AND tenant_id=?`), id, id); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRun(ctx, run, request); err == nil {
		t.Fatal("v2 run adopted an unverified legacy session")
	}
	if err := store.RecordRunResult(ctx, run, id, map[string]any{"answer": "answer a"}); err == nil {
		t.Fatal("v2 result adopted an unverified legacy session")
	}
	legacy, err := store.Detail(ctx, scope, id)
	if err != nil || legacy.InstallationID != "" || legacy.MessageCount != 2 {
		t.Fatalf("rejected adoption changed old data: %+v, %v", legacy, err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET installation_id=? WHERE id=? AND tenant_id=?`), run.InstallationID, id, id); err != nil {
		t.Fatal(err)
	}
	summary, err := store.Detail(ctx, scope, id)
	if err != nil || summary.InstallationID != run.InstallationID || summary.MessageCount != 2 {
		t.Fatalf("session provenance/count changed: %+v, %v", summary, err)
	}
	page, err := store.List(ctx, scope, Query{})
	if err != nil || len(page.Items) != 1 || page.Items[0].InstallationID != run.InstallationID {
		t.Fatalf("list lost installation: %+v, %v", page, err)
	}
	messages, _, err := store.ListMessages(ctx, scope, id, 1, 100)
	if err != nil || len(messages) != 2 {
		t.Fatalf("messages changed: %v", err)
	}
	branch, err := store.Regenerate(ctx, scope, id, messages[0].ID, "original_snapshot")
	if err != nil {
		t.Fatal(err)
	}
	branched, err := store.Detail(ctx, scope, branch.BranchSessionID)
	if err != nil || branched.InstallationID != run.InstallationID || branched.OwnerID != "owner" {
		t.Fatalf("branch lost provenance: %+v, %v", branched, err)
	}
}

func TestSQLConversationConcurrentRevisionAndRegeneration(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("pg-revision-%d", time.Now().UnixNano())
	scope := Scope{TenantID: id, DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "owner"}
	if err := store.CreateSession(ctx, scope, Session{Summary: Summary{ID: id, Kind: "qa", AgentID: "fixture", AgentVersionID: "v1", Title: "Concurrent revision", Status: "active"}}); err != nil {
		t.Fatal(err)
	}
	message := Message{ID: id + "message", SessionID: id, Role: "assistant", Content: "original"}
	if err := store.AppendMessage(ctx, scope, message); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 20)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			_, err := store.ReviseMessage(ctx, scope, id, message.ID, fmt.Sprintf("edit-%d", i), "fixture", 0)
			results <- err
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Errorf("revision: %v", err)
		}
	}
	if successes != 1 || conflicts != 19 {
		t.Fatalf("revision race: successes=%d conflicts=%d", successes, conflicts)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_revision WHERE session_id=? AND is_current=TRUE`), id).Scan(&count); err != nil || count != 1 {
		t.Fatalf("current revisions=%d err=%v", count, err)
	}
	start = make(chan struct{})
	branches := make(chan Regeneration, 12)
	results = make(chan error, 12)
	for i := 0; i < 12; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			branch, err := store.Regenerate(ctx, scope, id, message.ID, "original_snapshot")
			if err != nil {
				results <- err
				return
			}
			branches <- branch
		}()
	}
	close(start)
	workers.Wait()
	close(branches)
	close(results)
	for err := range results {
		t.Errorf("regeneration: %v", err)
	}
	winner, total := "", 0
	for branch := range branches {
		total++
		if winner == "" {
			winner = branch.BranchSessionID
		}
		if winner != branch.BranchSessionID {
			t.Error("multiple regeneration branches")
		}
	}
	if total != 12 {
		t.Fatalf("regeneration results=%d", total)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_session WHERE id=?`), winner).Scan(&count); err != nil || count != 1 {
		t.Fatalf("branches=%d err=%v", count, err)
	}
}
