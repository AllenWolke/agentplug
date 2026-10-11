package capability

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestCancellationToolRegistrationIsAtomicAndLateCommitFencedPostgres(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, e := sqlutil.OpenPostgres(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s, e := NewSQLToolInvocationStore(db)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnsureSchema(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.SetCancellationRegistrar(func(context.Context, *sql.Tx, ToolReceiptQuery) error { return nil }); !errors.Is(e, compensation.ErrInvalid) {
		t.Fatal("registrar omitted admission fence", e)
	}
	scope := scopeFromHarness(capabilityContext())
	scope.RunID = fmt.Sprint("registration-", time.Now().UnixNano())
	scope.TraceID = scope.RunID
	q := ToolReceiptQuery{Scope: scope, CallID: "owned-call", Name: "owned.write", Fingerprint: strings.Repeat("a", 64), RuntimeAudit: &ToolRuntimeAuditBinding{Descriptor: RuntimeToolDescriptor{ExecutionType: "tool", Risk: "write", TimeoutSeconds: 3}, PolicyHash: strings.Repeat("b", 64)}}
	ctx = context.WithValue(ctx, toolReceiptContextKey{}, q)
	denied := false
	s.SetExecutionAdmission(func(_ context.Context, tx *sql.Tx, actual sharedkernel.Scope) error {
		if tx == nil || actual != scope {
			t.Fatal("admission scope mismatch")
		}
		if denied {
			return compensation.ErrPending
		}
		return nil
	})
	if _, e = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS cancellation_tool_registration_fixture(id TEXT PRIMARY KEY)`); e != nil {
		t.Fatal(e)
	}
	injected := true
	if e = s.SetCancellationRegistrar(func(ctx context.Context, tx *sql.Tx, actual ToolReceiptQuery) error {
		if actual.Scope != scope || actual.RuntimeAudit == nil {
			t.Fatal("metadata absent")
		}
		if _, e := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO cancellation_tool_registration_fixture(id) VALUES(?)`), scope.RunID); e != nil {
			return e
		}
		if injected {
			return errors.New("injected owner registration failure")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	r, replay, e := s.AcquireTool(ctx, ToolReceiptScopeHash(scope), q.CallID, q.Fingerprint, "owner", time.Minute)
	if e != nil || replay {
		t.Fatal(e)
	}
	if e = s.BeginTool(ctx, r.Lease); e == nil {
		t.Fatal("failed registration submitted tool")
	}
	var phase string
	var count int
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), r.ScopeHash, r.CallID).Scan(&phase); e != nil || phase != "preparing" {
		t.Fatal("phase not rolled back", phase, e)
	}
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM cancellation_tool_registration_fixture WHERE id=?`), scope.RunID).Scan(&count); e != nil || count != 0 {
		t.Fatal("registration not rolled back", count, e)
	}
	injected = false
	if e = s.BeginTool(ctx, r.Lease); e != nil {
		t.Fatal(e)
	}
	bound := context.WithValue(ctx, toolLeaseContextKey{}, r.Lease)
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	facts, e := s.ReadCancellationToolsTx(ctx, tx, scope)
	tx.Rollback()
	if e != nil || len(facts) != 1 || facts[0].Status != "running" || facts[0].Phase != "executing" {
		t.Fatal("owned facts lost", e)
	}
	denied = true
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	e = s.GuardToolCommit(bound, tx, q)
	tx.Rollback()
	if !errors.Is(e, compensation.ErrPending) {
		t.Fatal("late commit admitted despite cancellation", e)
	}
	if _, e = db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET recovery_query='{}' WHERE scope_hash=? AND call_id=?`), r.ScopeHash, r.CallID); e != nil {
		t.Fatal(e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.ReadCancellationToolsTx(ctx, tx, scope)
	tx.Rollback()
	if !errors.Is(e, compensation.ErrConflict) {
		t.Fatal("corrupt historical metadata treated as read-only", e)
	}
}
