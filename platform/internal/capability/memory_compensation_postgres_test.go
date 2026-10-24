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

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// The authority here is a named component fixture. Actual execution/IAM/tree
// and runtime wiring are separately verified; this is not an Agent stop test.
type memoryCompensationAuthority struct{}

func (memoryCompensationAuthority) guard(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, status string) error {
	var current, binding string
	var stopped bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,scope_digest,stopped FROM compensation_test_memory_run WHERE run_id=? FOR UPDATE`), scope.RunID).Scan(&current, &binding, &stopped); err != nil {
		return err
	}
	if binding != compensation.ScopeDigest(scope) || current != status || (status == "cancelling" && !stopped) {
		return compensation.ErrPending
	}
	return nil
}
func (a memoryCompensationAuthority) RegisterEffectTx(ctx context.Context, tx *sql.Tx, s compensation.Step) error {
	return a.guard(ctx, tx, s.Root, "running")
}
func (a memoryCompensationAuthority) BeginCancellationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, r uint64) error {
	return a.guard(ctx, tx, s, "cancelling")
}
func (a memoryCompensationAuthority) ConfirmStoppedTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, p compensation.StopProof) error {
	return a.guard(ctx, tx, s, "cancelling")
}
func (a memoryCompensationAuthority) GuardCompensationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope) error {
	return a.guard(ctx, tx, s, "cancelling")
}
func (a memoryCompensationAuthority) FinishCancellationTx(ctx context.Context, tx *sql.Tx, s sharedkernel.Scope, p compensation.StopProof) error {
	if err := a.guard(ctx, tx, s, "cancelling"); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE compensation_test_memory_run SET status='cancelled' WHERE run_id=?`), s.RunID)
	return err
}

type memoryUndoFixture struct {
	ctx         context.Context
	db          *sql.DB
	memory      *SQLMemoryStore
	coordinator *compensation.SQLStore
	scope       sharedkernel.Scope
	engine      *compensation.Engine
	key         string
}

func ownedMemoryUndo(t *testing.T) *memoryUndoFixture {
	t.Helper()
	dsn := os.Getenv("COMPENSATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated owned PostgreSQL fixture required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !strings.HasPrefix(cfg.Database, "agentplug_compensation_test_") {
		t.Fatal("dedicated test database required; credentials suppressed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	t.Cleanup(func() { db.Close() })
	if err = compensation.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	facade := sqlutil.TransactionDB(tx)
	err = compensation.ApplyLocalEffectSchema(ctx, facade)
	facade.Close()
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	memory, err := NewSQLMemoryStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = memory.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = MigrateMemoryCompensation(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS compensation_test_memory_run(run_id TEXT PRIMARY KEY,scope_digest TEXT NOT NULL,status TEXT NOT NULL,stopped BOOLEAN NOT NULL DEFAULT FALSE)`); err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant-undo", DepartmentID: "dept-undo", ApplicationID: "app-undo", AgentID: "agent-memory", AgentInstanceID: "instance-memory", InstallationID: "install-memory", AgentVersionID: "version-memory", PrincipalID: "principal-memory", PrincipalType: "user", AuthorizationEpoch: 1, RunID: fmt.Sprintf("memory-undo-%d", time.Now().UnixNano()), TraceID: "trace-memory"}
	scope.SessionID = scope.RunID + "-session"
	if scope.ValidateTrusted() != nil {
		t.Fatal("invalid fixture scope")
	}
	if _, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO compensation_test_memory_run VALUES(?,?,'running',FALSE)`), scope.RunID, compensation.ScopeDigest(scope)); err != nil {
		t.Fatal(err)
	}
	coordinator, err := compensation.NewSQLStore(db, memoryCompensationAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := compensation.NewLocalEffectLedger(ctx, db, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	if err = memory.SetCancellationCompensation(ledger, func(_ context.Context, _ *sql.Tx, s sharedkernel.Scope) (sharedkernel.Scope, error) { return s, nil }); err != nil {
		t.Fatal(err)
	}
	registration, err := memory.MemoryCompensationRegistration()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := compensation.NewEngine(coordinator, "memory-undo-worker", registration)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryUndoFixture{ctx: ctx, db: db, memory: memory, coordinator: coordinator, scope: scope, engine: engine, key: scope.RunID + "\x00namespace\x00key"}
}
func (f *memoryUndoFixture) save(t *testing.T, call, value string) {
	t.Helper()
	raw, _ := json.Marshal(value)
	ctx := context.WithValue(f.ctx, memoryMutationKey{}, memoryMutation{Scope: f.scope, CallID: call, Fingerprint: memoryHash(string(raw))})
	if err := f.memory.Save(ctx, f.key, memoryEntry{Value: map[string]any{"text": value}, ExpiresAt: time.Now().Add(time.Hour)}, 10); err != nil {
		t.Fatal(err)
	}
}
func (f *memoryUndoFixture) stop(t *testing.T) {
	t.Helper()
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, sqlutil.Bind(`UPDATE compensation_test_memory_run SET status='cancelling',stopped=TRUE WHERE run_id=?`), f.scope.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.coordinator.BeginTx(f.ctx, tx, f.scope, 2); err != nil {
		t.Fatal(err)
	}
	if err = f.coordinator.ConfirmStoppedTx(f.ctx, tx, f.scope, compensation.StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: compensation.ScopeDigest(f.scope), Revision: 2, EvidenceDigest: memoryHash("fixture stopped")}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryCompensationReverseOrderAndForwardIdempotencyPostgres(t *testing.T) {
	f := ownedMemoryUndo(t)
	f.save(t, "first", "first value")
	f.save(t, "second", "second value")
	f.save(t, "second", "second value") // does not overwrite its own before-image
	f.stop(t)
	if _, err := f.engine.Tick(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	entry, exists, err := f.memory.Load(f.ctx, f.key)
	if err != nil || !exists || entry.Value["text"] != "first value" {
		t.Fatalf("predecessor not restored: %v %v", exists, err)
	}
	if _, err = f.engine.Tick(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	_, exists, err = f.memory.Load(f.ctx, f.key)
	if err != nil || exists {
		t.Fatalf("initial absence not restored: %v %v", exists, err)
	}
	if err = f.coordinator.TryFinalize(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryCompensationPreservesEvenSameValueConcurrentWriterPostgres(t *testing.T) {
	f := ownedMemoryUndo(t)
	f.save(t, "first", "same value")
	// An ordinary write gets a fresh owner stamp, even if its value is equal.
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_memory_entry SET value_json=value_json WHERE scope_key=?`), memoryHash(f.key)); err != nil {
		t.Fatal(err)
	}
	f.stop(t)
	if _, err := f.engine.Tick(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	entry, exists, err := f.memory.Load(f.ctx, f.key)
	if err != nil || !exists || entry.Value["text"] != "same value" {
		t.Fatal("concurrent value erased")
	}
	if err = f.coordinator.TryFinalize(f.ctx, f.scope); !errors.Is(err, compensation.ErrPending) {
		t.Fatalf("conflict accepted: %v", err)
	}
}

func TestMemoryCompensationMissingBindingAndLateForwardAreDeniedPostgres(t *testing.T) {
	f := ownedMemoryUndo(t)
	if err := f.memory.Save(f.ctx, f.key, memoryEntry{Value: map[string]any{"text": "unbound"}, ExpiresAt: time.Now().Add(time.Hour)}, 10); !errors.Is(err, compensation.ErrInvalid) {
		t.Fatalf("unbound memory admitted: %v", err)
	}
	f.save(t, "first", "owned")
	f.stop(t)
	ctx := context.WithValue(f.ctx, memoryMutationKey{}, memoryMutation{Scope: f.scope, CallID: "late", Fingerprint: memoryHash("late")})
	if err := f.memory.Save(ctx, f.key, memoryEntry{Value: map[string]any{"text": "late"}, ExpiresAt: time.Now().Add(time.Hour)}, 10); !errors.Is(err, compensation.ErrPending) {
		t.Fatalf("late write admitted: %v", err)
	}
}

func TestMemoryCompensationTransactionContextOwnsAuthorizationCallbacksPostgres(t *testing.T) {
	f := ownedMemoryUndo(t)
	type transactionKey struct{}
	var bound *sql.Tx
	if err := f.memory.SetCancellationTransactionContext(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) context.Context {
		if scope != f.scope || tx == nil {
			t.Fatal("wrong transaction scope")
		}
		bound = tx
		return context.WithValue(ctx, transactionKey{}, tx)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.memory.SetCancellationTransactionContext(func(ctx context.Context, _ *sql.Tx, _ sharedkernel.Scope) context.Context { return ctx }); !errors.Is(err, compensation.ErrInvalid) {
		t.Fatal("startup binding replaced during execution")
	}
	executionFenced := false
	f.memory.SetExecutionContinuityGuard(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
		common, present, err := sqlutil.ContinuityTransaction(ctx, f.db)
		if err != nil || !present || common != tx || tx != bound || scope != f.scope {
			return errors.New("memory execution continuity escaped owner")
		}
		executionFenced = true
		return nil
	})
	f.memory.SetAuthorizationContinuityGuard(func(ctx context.Context, tx *sql.Tx) error {
		if !executionFenced {
			return errors.New("IAM taken before execution parent protocol")
		}
		if tx != bound || ctx.Value(transactionKey{}) != tx {
			t.Fatal("continuity guard detached")
		}
		return nil
	})
	ctx := context.WithValue(f.ctx, memoryMutationKey{}, memoryMutation{Scope: f.scope, CallID: "bound-memory", Fingerprint: memoryHash("bound-value")})
	checks := 0
	err := f.memory.SaveAuthorized(ctx, f.key, memoryEntry{Value: map[string]any{"text": "bound-value"}, ExpiresAt: time.Now().Add(time.Minute)}, 10, func(ctx context.Context) error {
		if ctx.Value(transactionKey{}) != bound {
			t.Fatal("current-authority callback opened a separate transaction")
		}
		if err := bound.QueryRowContext(ctx, `SELECT 1`).Scan(new(int)); err != nil {
			return err
		}
		checks++
		return nil
	})
	if err != nil || checks != 2 {
		t.Fatalf("bound memory commit failed: checks=%d error=%v", checks, err)
	}
	f.stop(t)
	if _, err = f.engine.Tick(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
	if err = f.coordinator.TryFinalize(f.ctx, f.scope); err != nil {
		t.Fatal(err)
	}
}
