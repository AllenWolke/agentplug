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

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type runtimeAuditFailure struct {
	real audit.TxRecorder
	fail bool
}

func (a *runtimeAuditFailure) RecordTx(tx *sql.Tx, e audit.Event) error {
	if err := a.real.RecordTx(tx, e); err != nil {
		return err
	}
	if a.fail {
		return errors.New("injected failure after audit and outbox writes")
	}
	return nil
}

// Deferred to the owned overall PostgreSQL suite: proves rollback of all three
// records and that reconciliation cannot manufacture a second execution.
func TestRuntimeToolAuditLedgerOutboxAtomicityPostgres(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned overall PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLToolInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	outbox := notification.NewSQLStore(db)
	recorder := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{store.EnsureSchema, outbox.EnsureSchema, recorder.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	fault := &runtimeAuditFailure{real: recorder, fail: true}
	store.SetAuditRecorder(fault)
	scope := scopeFromHarness(capabilityContext())
	scope.RunID = fmt.Sprintf("runtime-audit-%d", time.Now().UnixNano())
	scope.TraceID = scope.RunID
	hash := ToolReceiptScopeHash(scope)
	q := ToolReceiptQuery{Scope: scope, CallID: "step-one", Name: "fixture.read", Fingerprint: strings.Repeat("a", 64),
		RuntimeAudit: &ToolRuntimeAuditBinding{Descriptor: RuntimeToolDescriptor{ExecutionType: "tool", Risk: "read_only", TimeoutSeconds: 3}, PolicyHash: strings.Repeat("b", 64)}}
	q.InputEvidence = toolInputEvidence(map[string]any{"note": "SENSITIVE_AUDIT_SENTINEL", "password": "private-input-marker"})
	ctx = context.WithValue(ctx, toolReceiptContextKey{}, q)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		for _, item := range []struct {
			query string
			arg   any
		}{
			{`DELETE FROM platform_notification_outbox WHERE partition_key=?`, scope.RunID},
			{`DELETE FROM platform_audit_event WHERE aggregate_type='run' AND aggregate_id=?`, scope.RunID},
			{`DELETE FROM platform_tool_invocation WHERE scope_hash=?`, hash},
		} {
			if _, err := db.ExecContext(cleanup, sqlutil.Bind(item.query), item.arg); err != nil {
				t.Error("owned audit fixture cleanup failed")
			}
		}
	}()
	invocation, replay, err := store.AcquireTool(ctx, hash, q.CallID, q.Fingerprint, "audit-fixture", 30*time.Second)
	if err != nil || replay {
		t.Fatalf("acquire: replay=%v error=%v", replay, err)
	}
	assertState := func(phase, status string, count int) {
		t.Helper()
		var gotPhase, gotStatus string
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase,status FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), hash, q.CallID).Scan(&gotPhase, &gotStatus); err != nil {
			t.Fatal(err)
		}
		if gotPhase != phase || gotStatus != status {
			t.Fatalf("state=%s/%s", gotPhase, gotStatus)
		}
		for _, query := range []string{`SELECT count(*) FROM platform_audit_event WHERE aggregate_type='run' AND aggregate_id=?`, `SELECT count(*) FROM platform_notification_outbox WHERE partition_key=?`} {
			var actual int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(query), scope.RunID).Scan(&actual); err != nil || actual != count {
				t.Fatalf("atomic records=%d expected=%d error=%v", actual, count, err)
			}
		}
	}
	store.SetExecutionAdmission(func(_ context.Context, tx *sql.Tx, actual sharedkernel.Scope) error {
		if tx == nil || actual != scope {
			t.Fatal("budget guard lacked owning transaction or original scope")
		}
		return usagecost.ErrBudgetExceeded
	})
	if err := store.BeginTool(ctx, invocation.Lease); !errors.Is(err, usagecost.ErrBudgetExceeded) {
		t.Fatal("exhausted budget admitted tool execution")
	}
	assertState("preparing", "running", 0)
	store.SetExecutionAdmission(nil)
	if err := store.BeginTool(ctx, invocation.Lease); err == nil {
		t.Fatal("audit failure admitted execution")
	}
	assertState("preparing", "running", 0)
	fault.fail = false
	if err := store.BeginTool(ctx, invocation.Lease); err != nil {
		t.Fatal(err)
	}
	assertState("executing", "running", 1)
	started := time.Now().UTC()
	obs, output := newToolObservation(scope, q.Name, q.CallID, &started, "succeeded", "completed", "", map[string]any{"private_content": "SENSITIVE_AUDIT_SENTINEL"})
	result := storedToolObservation(obs, output)
	fault.fail = true
	if err := store.FinishTool(ctx, invocation.Lease, result); err == nil {
		t.Fatal("audit failure committed result")
	}
	assertState("executing", "running", 1)
	fault.fail = false
	if err := store.UnknownTool(ctx, invocation.Lease); err != nil {
		t.Fatal(err)
	}
	assertState("executing", "unknown", 2)
	if _, _, err := store.AcquireTool(ctx, hash, q.CallID, q.Fingerprint, "second-worker", 30*time.Second); !errors.Is(err, ErrToolResultUnknown) {
		t.Fatal("unknown attempt became executable")
	}
	if err := store.RestoreCommitted(ctx, hash, q.CallID, q.Fingerprint, result); err != nil {
		t.Fatal(err)
	}
	assertState("executing", "completed", 3)
	if err := store.RestoreCommitted(ctx, hash, q.CallID, q.Fingerprint, result); err != nil {
		t.Fatal(err)
	}
	assertState("executing", "completed", 3)
	var leaked int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_audit_event WHERE aggregate_id=? AND summary LIKE ?`), scope.RunID, "%SENSITIVE_AUDIT_SENTINEL%").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("runtime audit retained input or output body")
	}
}
