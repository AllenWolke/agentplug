package capability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAutomaticToolRecoveryHoldsPreserveUnknownAndAdmitNewScope(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	c := capabilityContext()
	c.TaskID = fmt.Sprintf("held-tool-%d", time.Now().UnixNano())
	heldScope := scopeFromHarness(c)
	heldHash := ToolReceiptScopeHash(heldScope)
	c.TaskID += "-new"
	newScope := scopeFromHarness(c)
	newHash := ToolReceiptScopeHash(newScope)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash IN (?,?)`), heldHash, newHash); err != nil {
			t.Error(err)
		}
	}()
	var heldLease ToolExecutionLease
	for i := 0; i < 33; i++ {
		q := ToolReceiptQuery{Scope: heldScope, CallID: fmt.Sprintf("old-%02d", i), Name: "fixture.write", Fingerprint: "fp"}
		acquire := context.WithValue(ctx, toolReceiptContextKey{}, q)
		r, _, err := s.AcquireTool(acquire, heldHash, q.CallID, q.Fingerprint, "old-owner", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		heldLease = r.Lease
		if err = s.BeginTool(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
		if err = s.UnknownTool(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
	}
	var before string
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT jsonb_agg(to_jsonb(r) ORDER BY call_id)::text FROM platform_tool_invocation r WHERE scope_hash=?`), heldHash).Scan(&before); err != nil {
		t.Fatal(err)
	}
	q := ToolReceiptQuery{Scope: newScope, CallID: "fresh", Name: "fixture.write", Fingerprint: "fp"}
	r, _, err := s.AcquireTool(context.WithValue(ctx, toolReceiptContextKey{}, q), newHash, q.CallID, q.Fingerprint, "new-owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BeginTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	if err = s.UnknownTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	port := &receiptBusinessPort{query: q, result: map[string]any{"issue_id": "fresh-original-receipt"}}
	for restart := 0; restart < 2; restart++ {
		reopened, err := NewSQLToolInvocationStore(db)
		if err != nil {
			t.Fatal(err)
		}
		holds, err := sharedkernel.NewRecoveryHolds([]string{heldHash})
		if err != nil {
			t.Fatal(err)
		}
		if err = reopened.SetAutomaticRecoveryHolds(holds); err != nil {
			t.Fatal(err)
		}
		rows, err := reopened.ListToolRecovery(ctx, 64)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.ScopeHash == heldHash {
				t.Fatal("historical scope consumed page capacity")
			}
		}
		module := &Module{toolStore: reopened, tools: port}
		module.reconcileTools(ctx)
		for _, action := range []func(context.Context, ToolExecutionLease) error{reopened.RecoverToolPreparation, reopened.ExpireSubmittedTool, reopened.DeferToolRecovery} {
			if err := action(ctx, heldLease); !errors.Is(err, sharedkernel.ErrAutomaticRecoveryHeld) {
				t.Fatal("direct recovery bypassed hold", err)
			}
		}
		var after string
		if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT jsonb_agg(to_jsonb(r) ORDER BY call_id)::text FROM platform_tool_invocation r WHERE scope_hash=?`), heldHash).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after || port.calls != 0 {
			t.Fatal("history changed or business command replayed")
		}
	}
	var status string
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_tool_invocation WHERE scope_hash=? AND call_id='fresh'`), newHash).Scan(&status); err != nil || status != "completed" {
		t.Fatal("new receipt recovery starved", err, status)
	}
}
