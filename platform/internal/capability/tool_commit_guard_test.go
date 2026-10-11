package capability

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLToolCommitGuardRejectsMissingForgedAndExpiredProof(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	c := capabilityContext()
	q := ToolReceiptQuery{Scope: scopeFromHarness(c), CallID: fmt.Sprintf("guard-%d", time.Now().UnixNano()), Name: "fixture.write", Fingerprint: "fingerprint"}
	r, _, err := s.AcquireTool(ctx, ToolReceiptScopeHash(q.Scope), q.CallID, q.Fingerprint, "worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(sqlutil.Bind(`DELETE FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), r.ScopeHash, r.CallID); err != nil {
			t.Error(err)
		}
	}()
	if err := s.BeginTool(ctx, r.Lease); err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context, wantError bool) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		err = s.GuardToolCommit(ctx, tx, q)
		if wantError && !errors.Is(err, ErrToolInvocationConflict) {
			t.Fatal("invalid transaction proof admitted", err)
		}
		if !wantError && err != nil {
			t.Fatal(err)
		}
	}
	check(ctx, true)
	forged := r.Lease
	forged.Fence++
	check(context.WithValue(ctx, toolLeaseContextKey{}, forged), true)
	bound := context.WithValue(ctx, toolLeaseContextKey{}, r.Lease)
	check(bound, false)
	renewed, err := s.RenewTool(ctx, r.Lease, 2*time.Minute)
	if err != nil || !renewed.Until.After(r.Lease.Until) {
		t.Fatalf("renew lease: %+v %v", renewed, err)
	}
	if _, err := db.Exec(sqlutil.Bind(`UPDATE platform_tool_invocation SET lease_until=clock_timestamp() - INTERVAL '1 second' WHERE scope_hash=? AND call_id=?`), r.ScopeHash, r.CallID); err != nil {
		t.Fatal(err)
	}
	check(bound, true)
	if _, err := s.RenewTool(ctx, r.Lease, time.Minute); !errors.Is(err, ErrToolInvocationConflict) {
		t.Fatalf("expired lease resurrected: %v", err)
	}
}
