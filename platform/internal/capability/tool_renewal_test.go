package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Run the same ownership invariants against memory and the real SQL store.
// 内存与真实数据库执行同一组续租所有权断言，禁止过期复活。
func TestToolRenewalOwnership(t *testing.T) {
	check := func(t *testing.T, s ToolExecutionLeaseStore, renewal ToolLeaseRenewalStore, expire func(ToolExecutionLease)) {
		ctx := context.Background()
		r, _, err := s.AcquireTool(ctx, strings.Repeat("a", 64), fmt.Sprintf("renew-%d", time.Now().UnixNano()), strings.Repeat("b", 64), "worker", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := renewal.RenewTool(ctx, r.Lease, time.Second); !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("preparing execution was renewed")
		}
		if err := s.BeginTool(ctx, r.Lease); err != nil {
			t.Fatal(err)
		}
		forged := r.Lease
		forged.Fence++
		if _, err := renewal.RenewTool(ctx, forged, time.Second); !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("forged generation renewed")
		}
		updated, err := renewal.RenewTool(ctx, r.Lease, 10*time.Second)
		if err != nil || !updated.Until.After(r.Lease.Until) {
			t.Fatal("live generation was not extended")
		}
		expire(r.Lease)
		if _, err := renewal.RenewTool(ctx, r.Lease, time.Second); !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("expired execution resurrected")
		}
		if err := s.FinishTool(ctx, r.Lease, map[string]any{"ok": true}); !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("expired execution completed")
		}
	}
	t.Run("memory", func(t *testing.T) {
		s := newMemoryToolInvocationStore()
		check(t, s, s, func(l ToolExecutionLease) {
			s.mu.Lock()
			defer s.mu.Unlock()
			key := l.ScopeHash + "\x00" + l.CallID
			r := s.records[key]
			r.Lease.Until = time.Now().Add(-time.Second)
			s.records[key] = r
		})
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
		if dsn == "" {
			t.Skip("isolated PostgreSQL fixture not configured")
		}
		db, err := sqlutil.OpenPostgres(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		s, err := NewSQLToolInvocationStore(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
		check(t, s, s, func(l ToolExecutionLease) {
			if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE scope_hash=? AND call_id=?`), l.ScopeHash, l.CallID); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := db.Exec(sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), l.ScopeHash, l.CallID); err != nil {
					t.Error(err)
				}
			})
		})
	})
}

type unavailableToolRenewal struct{}

func (unavailableToolRenewal) RenewTool(context.Context, ToolExecutionLease, time.Duration) (ToolExecutionLease, error) {
	return ToolExecutionLease{}, errors.New("dependency unavailable")
}

func TestToolLeaseWatchCancelsOnRenewalFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	w := (&Module{}).watchToolLease(ctx, cancel, ToolExecutionLease{}, time.Second, envelope{}, unavailableToolRenewal{})
	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatal("renewal failed to cancel execution promptly")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("execution continued without a lease")
	}
	if w.finish() {
		t.Fatal("failed renewal reported success")
	}
}

func TestToolLeaseWatchExtendsLongExecutionAndJoins(t *testing.T) {
	s := newMemoryToolInvocationStore()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, _, err := s.AcquireTool(ctx, "scope", "long", "fp", "worker", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	w := (&Module{}).watchToolLease(ctx, cancel, r.Lease, time.Second, envelope{}, s)
	timer := time.NewTimer(1400 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("live execution cancelled")
	case <-timer.C:
	}
	if !w.finish() {
		t.Fatal("live renewal failed")
	}
	if err := s.FinishTool(ctx, r.Lease, map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenewTool(ctx, r.Lease, time.Second); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatal("terminal execution renewed")
	}
}

func TestToolLeaseWatchCancelsOnLiveAuthorityWithdrawal(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := capabilityContext()
	c.PlatformContextToken = signedContextToken(t, private, c, time.Now().Unix()-1, time.Now().Unix()+120)
	m := &Module{}
	m.SetLiveExecutionAuthority(testLiveAuthorityFunc(func(context.Context, sharedkernel.Scope, string, string, string) error {
		return errors.New("authorization withdrawn")
	}))
	s := newMemoryToolInvocationStore()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, _, err := s.AcquireTool(ctx, "scope", "revoked", "fp", "worker", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	w := m.watchToolLease(ctx, cancel, r.Lease, time.Second, envelope{Context: c}, s)
	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Fatal("authority withdrawal did not stop execution")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked execution continued")
	}
	if w.finish() {
		t.Fatal("authority withdrawal reported success")
	}
}
