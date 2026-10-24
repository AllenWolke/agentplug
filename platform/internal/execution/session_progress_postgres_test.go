package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLLatestSessionProgressIsolationAndOutcomeRevision(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal("isolated fixture open failed")
	}
	defer store.Close()
	prefix := fmt.Sprintf("session-progress-%d", time.Now().UnixNano())
	scope := testScope(prefix).domain()
	scope.SessionID = prefix
	ids := []string{prefix + "-first", prefix + "-next"}
	defer func() {
		for _, id := range ids {
			_, _ = store.db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_execution_outcome WHERE run_id=?`), id)
			_, _ = store.db.ExecContext(context.Background(), sqlutil.Bind(`DELETE FROM platform_execution_run WHERE run_id=?`), id)
		}
	}()
	for i, id := range ids {
		scope.RunID = id
		if _, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='waiting',revision=4,created_at=? WHERE run_id=?`), time.Now().Add(time.Duration(i)*time.Second), id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_outcome(run_id,revision,output_json,event_type,event_payload,projection_pending) VALUES(?,4,'{"stage":"waiting_review","draft":"private"}','waiting','{}',FALSE)`), ids[1]); err != nil {
		t.Fatal(err)
	}
	read := func(expected bool) {
		t.Helper()
		value, err := store.LatestSessionProgress(ctx, scope)
		if err != nil || value == nil || value.RunID != ids[1] || value.WaitingReview != expected {
			t.Fatal("incorrect latest progress", value, err)
		}
	}
	read(true)
	for _, test := range []struct {
		input string
		want  bool
	}{
		{`{"decision":"request_changes","comment":"补充适用制度及条款原文","reviewer_id":"independent-reviewer","draft":"must-not-leak"}`, true},
		{`{"decision":"approve","comment":"not feedback","reviewer_id":"independent-reviewer"}`, false},
		{`{"decision":"request_changes","comment":"","reviewer_id":"independent-reviewer"}`, false},
		{`{"decision":"request_changes","comment":"materials","reviewer_id":"` + scope.PrincipalID + `"}`, false},
		{`{"decision":"request_changes","comment":"materials"}`, false},
	} {
		if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json=? WHERE run_id=?`), test.input, ids[1]); err != nil {
			t.Fatal(err)
		}
		value, err := store.LatestSessionProgress(ctx, scope)
		if err != nil || value == nil || (value.ReviewFeedback != nil) != test.want {
			t.Fatal("unsafe or missing reviewer feedback", value, err)
		}
		encoded, _ := json.Marshal(value)
		if strings.Contains(string(encoded), "must-not-leak") {
			t.Fatal("arbitrary resume content leaked")
		}
	}
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json='{"decision":"request_changes","comment":"materials","reviewer_id":"independent-reviewer"}' WHERE run_id=?`), ids[1]); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*sharedkernel.Scope){func(s *sharedkernel.Scope) { s.TenantID = "other" }, func(s *sharedkernel.Scope) { s.DepartmentID = "other" }, func(s *sharedkernel.Scope) { s.ApplicationID = "other" }, func(s *sharedkernel.Scope) { s.PrincipalID = "other" }, func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" }, func(s *sharedkernel.Scope) { s.SessionID = "other" }, func(s *sharedkernel.Scope) { s.InstallationID = "other" }, func(s *sharedkernel.Scope) { s.AgentID = "other" }} {
		bad := scope
		change(&bad)
		if v, err := store.LatestSessionProgress(ctx, bad); err != nil || v != nil {
			t.Fatal("cross-scope progress leaked", v, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_outcome SET revision=3 WHERE run_id=?`), ids[1]); err != nil {
		t.Fatal(err)
	}
	read(false)
	value, err := store.LatestSessionProgress(ctx, scope)
	if err != nil || value.ReviewFeedback != nil {
		t.Fatal("stale outcome exposed reviewer feedback", value, err)
	}
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_outcome SET revision=4,event_type='task_completed' WHERE run_id=?`), ids[1]); err != nil {
		t.Fatal(err)
	}
	read(false)
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_outcome SET event_type='waiting',output_json='{"stage":"waiting_tool"}' WHERE run_id=?`), ids[1]); err != nil {
		t.Fatal(err)
	}
	read(false)
	if _, err := store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='succeeded' WHERE run_id=?`), ids[1]); err != nil {
		t.Fatal(err)
	}
	read(false)
}
