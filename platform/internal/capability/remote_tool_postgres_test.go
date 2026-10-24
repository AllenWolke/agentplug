package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
)

type remoteContractAuditFailure struct {
	real audit.TxRecorder
	fail bool
}

func TestSQLToolReceiptReadOptionalQueryIsStrict(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := NewSQLToolInvocationStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := mcpTestScope()
	scope.RunID = fmt.Sprintf("optional-query-%d", time.Now().UnixNano())
	q := ToolReceiptQuery{Scope: scope, CallID: "step", Name: "fixture.read", Fingerprint: strings.Repeat("a", 64)}
	row, _, err := store.AcquireTool(ctx, ToolReceiptScopeHash(scope), q.CallID, q.Fingerprint, "reader-fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := json.Marshal(q)
	wrong := q
	wrong.CallID = "other"
	wrongJSON, _ := json.Marshal(wrong)
	for _, item := range []struct {
		name           string
		raw            any
		valid, present bool
	}{
		{"sql-null", nil, true, false}, {"json-null", "null", true, false}, {"valid", string(good), true, true},
		{"empty-object", "{}", false, false}, {"malformed", "{bad", false, false}, {"wrong-identity", string(wrongJSON), false, false},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_invocation SET recovery_query=? WHERE scope_hash=? AND call_id=?`), item.raw, row.ScopeHash, row.CallID); err != nil {
				t.Fatal(err)
			}
			got, found, err := store.LookupToolInvocation(ctx, row.ScopeHash, row.CallID)
			if item.valid {
				if err != nil || !found || (got.ReceiptQuery != nil) != item.present {
					t.Fatal("optional query meaning changed", found, err)
				}
			} else if !errors.Is(err, ErrToolInvocationConflict) {
				t.Fatal("malformed object accepted", err)
			}
		})
	}
}

func (r *remoteContractAuditFailure) RecordTx(tx *sql.Tx, event audit.Event) error {
	if err := r.real.RecordTx(tx, event); err != nil {
		return err
	}
	if r.fail && event.Action == "runtime.tool.remote_contract" {
		return errors.New("injected remote contract audit failure")
	}
	return nil
}

func TestRemoteToolReceiptPostgresRestartAndAuditAtomicity(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, _ := NewSQLToolInvocationStore(db)
	outbox := notification.NewSQLStore(db)
	recorder := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{store.EnsureSchema, outbox.EnsureSchema, recorder.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	provider, command, contract, effects, lookups := remoteEffectFixture(t, "success")
	// The remote fixture fixes a Run identity internally. Use its exact scope,
	// and isolate the native rows in this suite's fresh database schema.
	fp, _ := ToolCommandFingerprint(command.Name, command.Payload)
	q := ToolReceiptQuery{Scope: command.Scope, Name: command.Name, CallID: command.CallID, Fingerprint: fp, RemoteContract: &contract,
		RuntimeAudit: &ToolRuntimeAuditBinding{Descriptor: RuntimeToolDescriptor{ExecutionType: "tool", Risk: "write", TimeoutSeconds: 5}, PolicyHash: strings.Repeat("b", 64)}}
	ctx = context.WithValue(ctx, toolReceiptContextKey{}, q)
	fault := &remoteContractAuditFailure{real: recorder, fail: true}
	store.SetAuditRecorder(fault)
	row, _, err := store.AcquireTool(ctx, ToolReceiptScopeHash(q.Scope), q.CallID, fp, "original-owner", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginTool(ctx, row.Lease); err == nil {
		t.Fatal("audit failure did not abort admission")
	}
	var phase string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT phase FROM platform_tool_invocation WHERE scope_hash=? AND call_id=?`), row.ScopeHash, row.CallID).Scan(&phase); err != nil || phase != "preparing" {
		t.Fatal("failed audit left execution admitted", phase, err)
	}
	for _, query := range []string{`SELECT count(*) FROM platform_audit_event WHERE aggregate_id=?`, `SELECT count(*) FROM platform_notification_outbox WHERE partition_key=?`} {
		var count int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(query), q.Scope.RunID).Scan(&count); err != nil || count != 0 {
			t.Fatal("ledger/audit/outbox transaction was split", count, err)
		}
	}
	fault.fail = false
	if err := store.BeginTool(ctx, row.Lease); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Invoke(ctx, command); err == nil || errors.Is(err, ErrToolNotSubmitted) {
		t.Fatal("lost HTTP result not retained as unknown", err)
	}
	if err := store.UnknownTool(ctx, row.Lease); err != nil {
		t.Fatal(err)
	}
	// Reopen both connection and ledger; do not copy in-memory receipts or send
	// the effect again. Recovery must load the original persisted contract.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	second, _ := NewSQLToolInvocationStore(reopened)
	second.SetAuditRecorder(audit.NewSQLStoreWithOutbox(reopened, notification.NewSQLStore(reopened)))
	dispatch, err := NewExecutionDispatcher(provider)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{tools: dispatch, toolStore: second}
	_, found, err := m.restoreBusinessTool(ctx, ToolReceiptQuery{Scope: q.Scope, Name: q.Name, CallID: q.CallID, Fingerprint: fp})
	if err != nil || !found || effects.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("restart duplicated or failed to recover effect", found, err, effects.Load(), lookups.Load())
	}
	saved, exists, err := second.LookupToolInvocation(ctx, row.ScopeHash, row.CallID)
	if err != nil || !exists || saved.Status != "completed" || saved.ReceiptQuery == nil || saved.ReceiptQuery.RemoteContract == nil || *saved.ReceiptQuery.RemoteContract != contract {
		t.Fatal("persistent identity/contract/result mismatch", err)
	}
	var summary string
	if err := reopened.QueryRowContext(ctx, sqlutil.Bind(`SELECT summary FROM platform_audit_event WHERE aggregate_id=? AND action='runtime.tool.remote_contract' ORDER BY created_at DESC LIMIT 1`), q.Scope.RunID).Scan(&summary); err != nil || !strings.Contains(summary, `"status":"receipt_reconciled"`) || strings.Contains(summary, "original-owner") {
		t.Fatal("actual recovery contract missing or owner token leaked", err)
	}
	t.Log(fmt.Sprintf("effect_calls=%d receipt_calls=%d original_result=completed audit_and_outbox=atomic", effects.Load(), lookups.Load()))
}
