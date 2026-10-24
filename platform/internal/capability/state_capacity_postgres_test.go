package capability

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Actual Save/lease/CAS/audit/Outbox transactions, not bulk inserted revisions.
// 4002 is the graph marker budget for 1000 issues * 2 confirmation boundaries
// * 2 marker writes plus the initial dispatch/exit. It is not a throughput gate.
func TestSQLCheckpointCapacityThousandIssueRecovery(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("owned migration and DML-only PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	owner, err := execution.ConnectSQLStore(ctx, "pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = execution.MigrateSchema(ctx, owner.DB()); err != nil {
		t.Fatal(err)
	}
	outbox := notification.NewSQLStore(owner.DB())
	if err = outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = audit.NewSQLStoreWithOutbox(owner.DB(), outbox).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	ownerStates, err := NewSQLCheckpointStore(owner.DB())
	if err != nil {
		t.Fatal(err)
	}
	if err = ownerStates.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	db := runs.DB()
	store, err := NewSQLCheckpointStore(db)
	if err != nil {
		t.Fatal(err)
	}
	store.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
	store.SetAuditRecorder(audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db)))
	id := fmt.Sprintf("checkpoint-capacity-%d", time.Now().UnixNano())
	scope := mcpTestScope()
	scope.RunID, scope.SessionID, scope.TraceID = id, id, id
	if _, err = runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "capacity-fixture"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, "checkpoint-worker", time.Now().UTC(), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(run.LeaseToken))
	write := StateWrite{Scope: scope, Lease: sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}, Namespace: "graph", Key: "marker", SchemaID: "schema://fixture/graph/v1", TTLSeconds: 3600, MaxEntries: 8192, MaxRevisions: 4096}
	allowed := func(context.Context) error { return nil }
	started := time.Now()
	var last Checkpoint
	for revision := uint64(1); revision <= 4002; revision++ {
		write.ExpectedRevision = revision - 1
		write.IdempotencyKey = fmt.Sprintf("advance-%d", revision)
		write.Value = map[string]any{"ordinal": revision}
		last, err = store.Save(ctx, write, allowed)
		if err != nil || last.Revision != revision {
			t.Fatalf("real transaction %d failed: %v", revision, err)
		}
		if revision == 64 || revision == 65 || revision%1000 == 0 {
			t.Logf("persisted revision=%d elapsed_ms=%d", revision, time.Since(started).Milliseconds())
		}
	}
	t.Run("reopen-capture-reference-and-fence-after-4002", func(t *testing.T) {
		reopened, _ := NewSQLCheckpointStore(db)
		loaded, found, err := reopened.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 4002)
		if err != nil || !found || loaded.ContentHash != last.ContentHash {
			t.Fatal("reopen lost exact durable state", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		var stopped uint64
		if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&stopped); err != nil {
			t.Fatal(err)
		}
		refs, err := reopened.CaptureRecoveryCheckpointsTx(ctx, tx, scope, stopped)
		if err != nil || len(refs) != 1 || refs[0].Revision != 4002 {
			t.Fatal("capture high revision failed", err, len(refs))
		}
		if err = reopened.LockCheckpointTx(ctx, tx, scope, write.Namespace, write.Key, loaded, true); err != nil {
			t.Fatal("high read fence failed", err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		recovered, err := reopened.LoadReference(ctx, scope, refs[0])
		if err != nil || recovered.ContentHash != last.ContentHash {
			t.Fatal("exact reference failed", err)
		}
		foreign := scope
		foreign.RunID += "-foreign"
		if _, err = reopened.LoadReference(ctx, foreign, refs[0]); err == nil {
			t.Fatal("reference crossed Run")
		}
		refs[0].Revision = contract.MaxCheckpointRevisions + 1
		if _, err = reopened.LoadReference(ctx, scope, refs[0]); err == nil {
			t.Fatal("overflow reference accepted")
		}
	})
	t.Run("idempotent-replay-and-stale-CAS-preserve-one-result", func(t *testing.T) {
		replayed, err := store.Save(ctx, write, allowed)
		if err != nil || replayed.Revision != 4002 || !replayed.ExpiresAt.Equal(last.ExpiresAt) {
			t.Fatal("replay changed state", err)
		}
		stale := write
		stale.IdempotencyKey = "different-stale-operation"
		if _, err = store.Save(ctx, stale, allowed); !errors.Is(err, ErrStateConflict) {
			t.Fatal("stale CAS accepted", err)
		}
		var count int
		if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_audit_event WHERE trace_id=? AND action='state.checkpoint.save'`), scope.TraceID).Scan(&count); err != nil || count != 4002 {
			t.Fatal("duplicate or missing audits", count, err)
		}
	})
	t.Run("published-upper-bound-and-legacy-default", func(t *testing.T) {
		legacy := write
		legacy.MaxRevisions = 0
		legacy.ExpectedRevision = 64
		legacy.IdempotencyKey = "legacy-overflow"
		if _, err = store.Save(ctx, legacy, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatal("legacy limit lost", err)
		}
		for revision := uint64(4003); revision <= 4096; revision++ {
			write.ExpectedRevision = revision - 1
			write.IdempotencyKey = fmt.Sprintf("advance-%d", revision)
			write.Value = map[string]any{"ordinal": revision}
			if _, err = store.Save(ctx, write, allowed); err != nil {
				t.Fatal(revision, err)
			}
		}
		write.ExpectedRevision = 4096
		write.IdempotencyKey = "overflow"
		if _, err = store.Save(ctx, write, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatal("absolute limit lost", err)
		}
		write.MaxRevisions = 4097
		write.ExpectedRevision = 0
		if _, err = store.Save(ctx, write, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatal("unbounded policy accepted", err)
		}
	})
	t.Run("cancelled-caller-cannot-append-after-reopen", func(t *testing.T) {
		cancelled, stop := context.WithCancel(ctx)
		stop()
		write.MaxRevisions = 4096
		write.ExpectedRevision = 4095
		write.IdempotencyKey = "cancelled"
		if _, err = store.Save(cancelled, write, allowed); err == nil {
			t.Fatal("cancelled caller wrote state")
		}
		loaded, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || !found || loaded.Revision != 4096 {
			t.Fatal("cancel changed final head", err)
		}
	})
}
