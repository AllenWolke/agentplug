package capability

import (
	"context"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestToolLeaseExpiredPreparationFencesOldWorker(t *testing.T) {
	s := newMemoryToolInvocationStore()
	ctx := context.Background()
	first, _, err := s.AcquireTool(ctx, "scope", "call", "fp", "owner-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	r := s.records["scope\x00call"]
	r.Lease.Until = time.Now().Add(-time.Second)
	s.records["scope\x00call"] = r
	s.mu.Unlock()
	second, _, err := s.AcquireTool(ctx, "scope", "call", "fp", "owner-b", time.Minute)
	if err != nil || second.Lease.Fence != first.Lease.Fence+1 || second.Lease.Token == first.Lease.Token {
		t.Fatal("expired preparation did not receive new generation")
	}
	for _, err := range []error{s.BeginTool(ctx, first.Lease), s.RejectTool(ctx, first.Lease), s.UnknownTool(ctx, first.Lease)} {
		if !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("old owner changed new attempt")
		}
	}
	if err := s.BeginTool(ctx, second.Lease); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, "scope", "call", "fp", map[string]any{"bad": true}); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("unfenced completion bypassed owned lease")
	}
	s.mu.Lock()
	r = s.records["scope\x00call"]
	r.Lease.Until = time.Now().Add(-time.Second)
	s.records["scope\x00call"] = r
	s.mu.Unlock()
	if _, _, err := s.AcquireTool(ctx, "scope", "call", "fp", "owner-c", time.Minute); !errors.Is(err, ErrToolResultUnknown) {
		t.Fatal("expired submitted execution was retried")
	}
}

func TestSQLToolLeaseContendersAndReopenFencing(t *testing.T) {
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
	scope, fp, id := strings.Repeat("e", 64), strings.Repeat("f", 64), fmt.Sprintf("tool-lease-%d", time.Now().UnixNano())
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), scope, id); err != nil {
			t.Error("lease fixture cleanup failed")
		}
	}()
	var winners atomic.Int32
	var wg sync.WaitGroup
	results := make(chan ToolInvocation, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, replay, err := s.AcquireTool(ctx, scope, id, fp, fmt.Sprintf("owner-%d", i), time.Minute)
			if err == nil && !replay {
				winners.Add(1)
				results <- r
			} else if !errors.Is(err, ErrToolInvocationPending) {
				t.Errorf("unexpected contender result: %v", err)
			}
		}(i)
	}
	wg.Wait()
	close(results)
	if winners.Load() != 1 {
		t.Fatal("multiple tool execution owners acquired")
	}
	first := <-results
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND call_id=?`), scope, id); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLToolInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := reopened.AcquireTool(ctx, scope, id, fp, "replacement", time.Minute)
	if err != nil || second.Lease.Fence != first.Lease.Fence+1 {
		t.Fatal("reopen did not fence expired preparation")
	}
	if err := s.BeginTool(ctx, first.Lease); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("stale SQL owner began replacement")
	}
	if err := reopened.BeginTool(ctx, second.Lease); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, scope, id, fp, map[string]any{"bad": true}); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("SQL unfenced completion bypassed lease")
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND call_id=?`), scope, id); err != nil {
		t.Fatal(err)
	}
	if err := reopened.FinishTool(ctx, second.Lease, map[string]any{"done": true}); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("expired owner completed")
	}
	if _, _, err := reopened.AcquireTool(ctx, scope, id, fp, "third", time.Minute); !errors.Is(err, ErrToolResultUnknown) {
		t.Fatal("expired SQL execution retried")
	}
	if err := s.RejectTool(ctx, first.Lease); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("stale SQL owner rejected unknown attempt")
	}
}
