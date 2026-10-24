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

func TestToolRecoveryIdlePollingBacksOffAndBusyPagesReset(t *testing.T) {
	interval := time.Second
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, expected := range want {
		interval = nextToolRecoveryInterval(interval, 0)
		if interval != expected {
			t.Fatalf("idle round %d interval=%s want %s", i+1, interval, expected)
		}
	}
	if got := nextToolRecoveryInterval(interval, -1); got != 30*time.Second {
		t.Fatalf("failed scans must remain bounded: %s", got)
	}
	if got := nextToolRecoveryInterval(interval, 1); got != toolRecoveryPollFloor {
		t.Fatalf("due records must restore the responsive interval: %s", got)
	}
}

func TestToolRecoveryLogRateLimit(t *testing.T) {
	m := &Module{}
	start := time.Now()
	if !m.allowToolRecoveryLog(start) || m.allowToolRecoveryLog(start.Add(toolRecoveryLogInterval-time.Nanosecond)) {
		t.Fatal("tool recovery logs were not rate limited")
	}
	if !m.allowToolRecoveryLog(start.Add(toolRecoveryLogInterval)) {
		t.Fatal("tool recovery log did not reopen after its interval")
	}
}

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
	ready := 0
	for time.Now().Before(deadline) {
		// A real worker polls the whole database. Earlier integration tests may
		// also own recoverable rows; global counters cannot identify our work.
		// Require the three exact durable outcomes, without filtering its scan.
		err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_tool_invocation WHERE scope_hash=? AND (
 (call_id='committed' AND status='completed') OR
 (call_id='preparing' AND status='failed') OR
 (call_id='corrupt-query' AND status='unknown' AND retry_after>clock_timestamp()))`), hash).Scan(&ready)
		if err != nil {
			t.Fatal(err)
		}
		if ready == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ready != 3 || m.toolStats.Completed.Load() < 2 || m.toolStats.Failed.Load() < 1 || port.calls != 0 {
		t.Fatalf("independent worker outcomes=%d completed=%d failed=%d business_calls=%d", ready, m.toolStats.Completed.Load(), m.toolStats.Failed.Load(), port.calls)
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

func TestSQLToolRecoveryBackoffScalesWithAgeAndStaysBounded(t *testing.T) {
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
	c.TaskID = fmt.Sprintf("tool-backoff-%d", time.Now().UnixNano())
	scope := scopeFromHarness(c)
	hash := ToolReceiptScopeHash(scope)
	for _, tc := range []struct {
		call     string
		age      string
		min, max time.Duration
	}{{"fresh", "0 seconds", 4 * time.Second, 6 * time.Second}, {"ten-minutes", "10 minutes", 55 * time.Second, 65 * time.Second}, {"one-hour", "1 hour", 295 * time.Second, 305 * time.Second}} {
		q := ToolReceiptQuery{Scope: scope, CallID: tc.call, Name: "fixture.write", Fingerprint: "fp"}
		r, _, err := s.AcquireTool(context.WithValue(ctx, toolReceiptContextKey{}, q), hash, q.CallID, q.Fingerprint, "owner", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET status='unknown',phase='executing',created_at=clock_timestamp()-CAST(? AS INTERVAL) WHERE scope_hash=? AND call_id=?`), tc.age, hash, tc.call); err != nil {
			t.Fatal(err)
		}
		if err := s.DeferToolRecovery(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
		var status string
		var wait float64
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,EXTRACT(EPOCH FROM retry_after-clock_timestamp()) FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), hash, tc.call).Scan(&status, &wait); err != nil {
			t.Fatal(err)
		}
		got := time.Duration(wait * float64(time.Second))
		if status != "unknown" || got < tc.min || got > tc.max {
			t.Fatalf("%s: status=%s backoff=%s want unknown within [%s,%s]", tc.call, status, got, tc.min, tc.max)
		}
	}
}
