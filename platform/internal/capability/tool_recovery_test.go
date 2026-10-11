package capability

import (
	"context"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"testing"
	"time"
)

func TestToolRecoveryIsBoundedAndUnknownNeverExecutes(t *testing.T) {
	s := newMemoryToolInvocationStore()
	ctx := context.Background()
	for i := 0; i < 17; i++ {
		r, _, err := s.AcquireTool(ctx, "scope", fmt.Sprintf("unknown-%02d", i), "fp", "owner", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.BeginTool(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
		if err := s.UnknownTool(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
	}
	m := &Module{toolStore: s, tools: &receiptBusinessPort{}}
	m.reconcileTools(ctx)
	if m.toolStats.Failed.Load() != 16 || m.toolStats.Completed.Load() != 0 {
		t.Fatal("recovery page was not bounded")
	}
	rows, err := s.ListToolRecovery(ctx, 16)
	if err != nil || len(rows) != 1 {
		t.Fatal("persistent backoff did not rotate unknown items")
	}
	m.reconcileTools(ctx)
	rows, err = s.ListToolRecovery(ctx, 16)
	if err != nil || len(rows) != 0 || m.toolStats.Failed.Load() != 17 {
		t.Fatal("unknown results were retried or not deferred")
	}
	if m.tools.(*receiptBusinessPort).calls != 0 {
		t.Fatal("recovery executed a business command")
	}
}

func TestSQLToolWorkerRecoversWithoutClientRetryAfterReopen(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	c := capabilityContext()
	c.TaskID = fmt.Sprintf("tool-worker-%d", time.Now().UnixNano())
	scope := scopeFromHarness(c)
	hash := ToolReceiptScopeHash(scope)
	q := ToolReceiptQuery{Scope: scope, CallID: "committed", Name: "fixture.write", Fingerprint: "fp"}
	acquireCtx := context.WithValue(ctx, toolReceiptContextKey{}, q)
	r, _, err := s.AcquireTool(acquireCtx, hash, q.CallID, q.Fingerprint, "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	if err := s.UnknownTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	prep, _, err := s.AcquireTool(ctx, hash, "preparing", "prepare-fp", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND call_id='preparing'`), hash); err != nil {
		t.Fatal(err)
	}
	bad, _, err := s.AcquireTool(ctx, hash, "corrupt-query", "bad-fp", "owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTool(ctx, bad.Lease); err != nil {
		t.Fatal(err)
	}
	if err := s.UnknownTool(ctx, bad.Lease); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET recovery_query='{' WHERE scope_hash=? AND call_id='corrupt-query'`), hash); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=?`), hash); err != nil {
			t.Error("tool worker fixture cleanup failed")
		}
	}()
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLToolInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	port := &receiptBusinessPort{query: q, result: map[string]any{"issue_id": "committed", "revision": float64(1)}}
	m := &Module{toolStore: reopened, tools: port}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := m.Close(closeCtx); err != nil {
			t.Error("worker shutdown failed")
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for m.toolStats.Completed.Load()+m.toolStats.Failed.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.toolStats.Completed.Load() != 2 || m.toolStats.Failed.Load() != 1 || port.calls != 0 {
		t.Fatal("independent worker failed or executed business command")
	}
	got, replay, err := reopened.AcquireTool(ctx, hash, q.CallID, q.Fingerprint, "another", time.Minute)
	if err != nil || !replay || got.Result["issue_id"] != "committed" {
		t.Fatal("worker did not restore durable committed result")
	}
	replacement, _, err := reopened.AcquireTool(ctx, hash, "preparing", "prepare-fp", "new-owner", time.Minute)
	if err != nil || replacement.Lease.Fence != prep.Lease.Fence+1 {
		t.Fatal("expired unsent preparation not recovered")
	}
	if err := s.BeginTool(ctx, prep.Lease); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("stale preparing worker resumed")
	}
	var badStatus string
	var deferred bool
	// The failure counter may precede the backoff commit; wait for durable proof.
	// 失败计数可能先于退避提交，必须等待数据库证据而非假设线程已结束。
	backoffDeadline := time.Now().Add(2 * time.Second)
	for !deferred && time.Now().Before(backoffDeadline) {
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,COALESCE(retry_after>clock_timestamp(),FALSE) FROM platform_tool_invocation WHERE scope_hash=? AND call_id='corrupt-query'`), hash).Scan(&badStatus, &deferred); err != nil {
			t.Fatal(err)
		}
		if !deferred {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if badStatus != "unknown" || !deferred {
		t.Fatal("corrupt query was released, retried or not deferred")
	}
}
