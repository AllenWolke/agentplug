package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type failingCheckpointAudit struct{}

type failingCheckpointOutbox struct{}

func (failingCheckpointOutbox) EnqueueTx(context.Context, *sql.Tx, notification.Event) (notification.Event, error) {
	return notification.Event{}, errors.New("controlled checkpoint Outbox failure")
}

func (failingCheckpointAudit) RecordTx(*sql.Tx, audit.Event) error {
	return errors.New("controlled audit transaction failure")
}

// Actual PostgreSQL and execution leases; the current-IAM callback is a
// controlled fixture, not a substitute for normal permission approval tests.
func TestSQLBusinessCheckpointCASRecoveryAndAuthority(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	runs, err := execution.ConnectSQLStore(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	if err = execution.MigrateSchema(ctx, runs.DB()); err != nil {
		t.Fatal(err)
	}
	db := runs.DB()
	outbox := notification.NewSQLStore(db)
	if err = outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	recorder := audit.NewSQLStoreWithOutbox(db, outbox)
	if err = recorder.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLCheckpointStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	store.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
	store.SetAuditRecorder(recorder)
	id := fmt.Sprintf("business-state-%d", time.Now().UnixNano())
	scope := mcpTestScope()
	scope.RunID, scope.SessionID, scope.TraceID = id, id, id
	scope.TenantID, scope.PrincipalID = id+"-tenant", id+"-user"
	_, err = runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "checkpoint-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := runs.AcquireLease(id, "checkpoint-worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runs.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(run.LeaseToken))
	write := StateWrite{Scope: scope, Lease: sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}, Namespace: "harness", Key: "loop", SchemaID: "schema://example/state/v1", IdempotencyKey: "first", Value: map[string]any{"sequence": json.Number("9007199254740993")}, TTLSeconds: 60, MaxEntries: 1}
	allowed := func(context.Context) error { return nil }
	var currentRecoveryReference contract.RecoveryCheckpointReference
	captureRecoverySnapshot := func(candidate sharedkernel.Scope) ([]contract.RecoveryCheckpointReference, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		var stoppedRevision int64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), id).Scan(&stoppedRevision); err != nil {
			return nil, err
		}
		if stoppedRevision < 1 {
			return nil, ErrStateUnavailable
		}
		return store.CaptureRecoveryCheckpointsTx(ctx, tx, candidate, uint64(stoppedRevision))
	}
	first, err := store.Save(ctx, write, allowed)
	if err != nil || first.Revision != 1 {
		t.Fatalf("first write: %+v %v", first, err)
	}
	t.Run("stable-replay", func(t *testing.T) {
		replayed, err := store.Save(ctx, write, allowed)
		if err != nil || replayed.ContentHash != first.ContentHash || !replayed.ExpiresAt.Equal(first.ExpiresAt) {
			t.Fatalf("replay changed: %+v %v", replayed, err)
		}
		changed := write
		changed.Value = map[string]any{"sequence": json.Number("9007199254740992")}
		if _, err = store.Save(ctx, changed, allowed); !errors.Is(err, ErrStateConflict) {
			t.Fatalf("input mutation accepted: %v", err)
		}
	})
	t.Run("concurrent-cas-single-winner", func(t *testing.T) {
		var winners, conflicts atomic.Int32
		var group sync.WaitGroup
		for i := 0; i < 8; i++ {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				attempt := write
				attempt.ExpectedRevision, attempt.IdempotencyKey = 1, fmt.Sprintf("contender-%d", index)
				attempt.Value = map[string]any{"winner": index}
				_, err := store.Save(ctx, attempt, allowed)
				if err == nil {
					winners.Add(1)
				} else if errors.Is(err, ErrStateConflict) {
					conflicts.Add(1)
				} else {
					t.Errorf("contender: %v", err)
				}
			}(i)
		}
		group.Wait()
		if winners.Load() != 1 || conflicts.Load() != 7 {
			t.Fatalf("CAS winners=%d conflicts=%d", winners.Load(), conflicts.Load())
		}
	})
	t.Run("reopen-and-history", func(t *testing.T) {
		reopened, err := NewSQLCheckpointStore(db)
		if err != nil {
			t.Fatal(err)
		}
		current, found, err := reopened.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || !found || current.Revision != 2 {
			t.Fatalf("current: %+v %v %v", current, found, err)
		}
		history, found, err := reopened.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 1)
		if err != nil || !found || history.Value["sequence"] != json.Number("9007199254740993") {
			t.Fatalf("history precision lost: %+v %v", history, err)
		}
		foreign := scope
		foreign.PrincipalID = "another-user"
		if _, found, err := reopened.Load(ctx, foreign, write.Namespace, write.Key, write.SchemaID, 0); err != nil || found {
			t.Fatalf("foreign state visible: %v %v", found, err)
		}
		if _, _, err := reopened.Load(ctx, scope, write.Namespace, write.Key, "schema://example/state/v2", 0); !errors.Is(err, ErrStateSchema) {
			t.Fatalf("schema mutation accepted: %v", err)
		}
	})
	t.Run("quota-and-generation", func(t *testing.T) {
		attempt := write
		attempt.Key, attempt.IdempotencyKey = "other", "quota"
		if _, err := store.Save(ctx, attempt, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatalf("quota bypass: %v", err)
		}
		attempt = write
		attempt.Lease.Revision++
		if _, err := store.Save(ctx, attempt, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatalf("foreign generation replay accepted: %v", err)
		}
		attempt = write
		attempt.Lease.TokenHash = fmt.Sprintf("%064d", 0)
		if _, err := store.Save(ctx, attempt, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatalf("forged lease accepted: %v", err)
		}
	})
	t.Run("audit-failure-atomic-rollback", func(t *testing.T) {
		store.SetAuditRecorder(failingCheckpointAudit{})
		defer store.SetAuditRecorder(recorder)
		attempt := write
		attempt.ExpectedRevision, attempt.IdempotencyKey = 2, "audit-failure"
		if _, err := store.Save(ctx, attempt, allowed); err == nil {
			t.Fatal("audit failure was ignored")
		}
		current, _, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || current.Revision != 2 {
			t.Fatalf("partial head committed: %+v %v", current, err)
		}
	})
	t.Run("post-lock-and-replay-authority", func(t *testing.T) {
		var checks atomic.Int32
		_, err := store.Save(ctx, write, func(context.Context) error {
			if checks.Add(1) >= 3 {
				return errors.New("current permission revoked before replay")
			}
			return nil
		})
		if !errors.Is(err, ErrStateDenied) || checks.Load() != 3 {
			t.Fatalf("replay authority not rechecked: checks=%d %v", checks.Load(), err)
		}
	})
	t.Run("outbox-failure-rolls-back-checkpoint-and-audit", func(t *testing.T) {
		store.SetAuditRecorder(audit.NewSQLStoreWithOutbox(db, failingCheckpointOutbox{}))
		defer store.SetAuditRecorder(recorder)
		attempt := write
		attempt.ExpectedRevision, attempt.IdempotencyKey = 2, "outbox-failure"
		if _, err := store.Save(ctx, attempt, allowed); err == nil {
			t.Fatal("Outbox failure was ignored")
		}
		current, _, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || current.Revision != 2 {
			t.Fatalf("partial state committed: %+v %v", current, err)
		}
		var events int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='state.checkpoint.save'`), scope.TraceID).Scan(&events); err != nil || events != 2 {
			t.Fatalf("partial audit committed: events=%d %v", events, err)
		}
	})
	t.Run("new-worker-generation-recovery", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET revision=revision+1 WHERE run_id=?`), id); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Save(ctx, write, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatalf("old generation accepted: %v", err)
		}
		attempt := write
		attempt.Lease.Revision++
		attempt.ExpectedRevision, attempt.IdempotencyKey = 2, "recovered-generation"
		latest, err := store.Save(ctx, attempt, allowed)
		if err != nil || latest.Revision != 3 || latest.ExecutionRevision != attempt.Lease.Revision {
			t.Fatalf("recovery: %+v %v", latest, err)
		}
	})
	t.Run("recovery-checkpoint-snapshot", func(t *testing.T) {
		current, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || !found || current.Revision != 3 {
			t.Fatalf("current checkpoint unavailable for snapshot: %+v found=%v err=%v", current, found, err)
		}
		refs, err := captureRecoverySnapshot(scope)
		if err != nil || len(refs) != 1 {
			t.Fatalf("snapshot did not capture its sole state lineage: %#v %v", refs, err)
		}
		_, stateKey, err := stateKeys(scope, write.Namespace, write.Key)
		if err != nil {
			t.Fatal(err)
		}
		ref := refs[0]
		if ref.StateKey != stateKey || ref.Revision != current.Revision || ref.SchemaID != current.SchemaID ||
			ref.ContentHash != current.ContentHash || ref.ExecutionRevision != current.ExecutionRevision || !ref.ExpiresAt.Equal(current.ExpiresAt) {
			t.Fatalf("snapshot metadata differs from current checkpoint: ref=%+v checkpoint=%+v", ref, current)
		}
		encoded, err := json.Marshal(refs)
		if err != nil || bytes.Contains(encoded, []byte("9007199254740993")) {
			t.Fatalf("snapshot exposed business checkpoint content: %s %v", encoded, err)
		}
		currentRecoveryReference = ref
		loaded, err := store.LoadReference(ctx, scope, ref)
		if err != nil || loaded.Revision != current.Revision || loaded.SchemaID != current.SchemaID ||
			loaded.ContentHash != current.ContentHash || loaded.ExecutionRevision != current.ExecutionRevision ||
			!loaded.ExpiresAt.Equal(current.ExpiresAt) || loaded.Value["sequence"] != json.Number("9007199254740993") {
			t.Fatalf("valid recovery reference did not restore its exact checkpoint: %+v %v", loaded, err)
		}
		foreign := scope
		foreign.PrincipalID = "another-user"
		if refs, err := captureRecoverySnapshot(foreign); !errors.Is(err, ErrStateContinuityLost) || len(refs) != 0 {
			t.Fatalf("foreign scope returned a recovery snapshot: %#v %v", refs, err)
		}
		if checkpoint, err := store.LoadReference(ctx, foreign, ref); err == nil || checkpoint.Value != nil {
			t.Fatalf("foreign scope loaded checkpoint data: %+v %v", checkpoint, err)
		}
		_, initialStateKey, err := stateKeys(scope, write.Namespace, write.Key)
		if err != nil {
			t.Fatal(err)
		}
		historical := contract.RecoveryCheckpointReference{
			StateKey: initialStateKey, Revision: first.Revision, SchemaID: first.SchemaID,
			ContentHash: first.ContentHash, ExecutionRevision: first.ExecutionRevision, ExpiresAt: first.ExpiresAt,
		}
		if checkpoint, err := store.LoadReference(ctx, scope, historical); !errors.Is(err, ErrStateConflict) || checkpoint.Value != nil {
			t.Fatalf("advanced head accepted a historical reference: %+v %v", checkpoint, err)
		}
		t.Run("renewal-reference-allows-only-exact-live-history", func(t *testing.T) {
			renewalID := id + "-renewal"
			renewalScope := scope
			renewalScope.RunID, renewalScope.SessionID, renewalScope.TraceID = renewalID, renewalID, renewalID
			_, renewalStateKey, err := stateKeys(renewalScope, "harness", "renewal-history")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanupCtx := context.Background()
				if _, cleanupErr := db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_business_checkpoint WHERE scope_key=?`), renewalStateKey); cleanupErr != nil {
					t.Errorf("delete renewal fixture checkpoint rows: %v", cleanupErr)
				}
				if _, cleanupErr := db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_business_state_head WHERE scope_key=?`), renewalStateKey); cleanupErr != nil {
					t.Errorf("delete renewal fixture state head: %v", cleanupErr)
				}
			})
			if _, err := runs.Create(platformruntime.CreateRequest{ID: renewalID, Scope: renewalScope,
				AgentVersionID: renewalScope.AgentVersionID, IdempotencyKey: renewalID, Fingerprint: "renewal-history"}); err != nil {
				t.Fatal(err)
			}
			claimed, err := runs.AcquireLease(renewalID, "renewal-history-worker", time.Now().UTC(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := runs.TransitionLeased(renewalID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
			if err != nil {
				t.Fatal(err)
			}
			leaseHash := sha256.Sum256([]byte(running.LeaseToken))
			write := StateWrite{Scope: renewalScope,
				Lease:     sharedkernel.ExecutionLeaseBinding{Revision: running.Revision, TokenHash: fmt.Sprintf("%x", leaseHash)},
				Namespace: "harness", Key: "renewal-history", SchemaID: "schema://example/renewal/v1",
				IdempotencyKey: "renewal-history-first", Value: map[string]any{"phase": "approval_required", "revision": 1},
				TTLSeconds: 60, MaxEntries: 8}
			first, err := store.Save(ctx, write, allowed)
			if err != nil {
				t.Fatal("write recovery checkpoint", err)
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var stoppedRevision int64
			if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_execution_run WHERE run_id=? FOR UPDATE`), renewalID).Scan(&stoppedRevision); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			references, captureErr := store.CaptureRecoveryCheckpointsTx(ctx, tx, renewalScope, uint64(stoppedRevision))
			_ = tx.Rollback()
			if captureErr != nil || len(references) != 1 {
				t.Fatalf("capture historical reference: refs=%+v err=%v", references, captureErr)
			}
			reference := references[0]
			write.ExpectedRevision = first.Revision
			write.IdempotencyKey = "renewal-history-advance"
			write.Value = map[string]any{"phase": "tool_running", "revision": 2}
			if _, err = store.Save(ctx, write, allowed); err != nil {
				t.Fatal("advance current State head", err)
			}
			if checkpoint, err := store.LoadReference(ctx, renewalScope, reference); !errors.Is(err, ErrStateConflict) || checkpoint.Value != nil {
				t.Fatalf("dispatch/public reference reader accepted an advanced head: %+v %v", checkpoint, err)
			}
			loaded, err := store.LoadRenewalReference(ctx, renewalScope, reference)
			if err != nil || loaded.Revision != first.Revision || loaded.ContentHash != first.ContentHash || loaded.ExecutionRevision != first.ExecutionRevision ||
				!loaded.ExpiresAt.Equal(first.ExpiresAt) || loaded.Value["phase"] != "approval_required" {
				t.Fatalf("renewal did not read the exact live historical payload: %+v %v", loaded, err)
			}
			badExecutionRevision := reference
			badExecutionRevision.ExecutionRevision++
			badSchemaID := reference
			badSchemaID.SchemaID = "schema://example/renewal/other"
			badExpiry := reference
			badExpiry.ExpiresAt = reference.ExpiresAt.Add(time.Second)
			for name, altered := range map[string]contract.RecoveryCheckpointReference{
				"execution revision": badExecutionRevision,
				"schema ID":          badSchemaID,
				"expiry":             badExpiry,
			} {
				if checkpoint, err := store.LoadRenewalReference(ctx, renewalScope, altered); !errors.Is(err, ErrStateConflict) || checkpoint.Value != nil {
					t.Fatalf("renewal accepted changed %s metadata: %+v %v", name, checkpoint, err)
				}
			}
			foreign := renewalScope
			foreign.PrincipalID += "-foreign"
			if checkpoint, err := store.LoadRenewalReference(ctx, foreign, reference); err == nil || checkpoint.Value != nil {
				t.Fatalf("renewal reference crossed its trusted scope: %+v %v", checkpoint, err)
			}
			badHash := reference
			badHash.ContentHash = strings.Repeat("0", 64)
			if checkpoint, err := store.LoadRenewalReference(ctx, renewalScope, badHash); !errors.Is(err, ErrStateConflict) || checkpoint.Value != nil {
				t.Fatalf("renewal accepted a changed checkpoint hash: %+v %v", checkpoint, err)
			}
			if _, err = db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE scope_key=? AND revision=?`), renewalStateKey, reference.Revision); err != nil {
				t.Fatal(err)
			}
			if checkpoint, err := store.LoadRenewalReference(ctx, renewalScope, reference); !errors.Is(err, ErrStateContinuityLost) || checkpoint.Value != nil {
				t.Fatalf("renewal accepted an expired historical payload: %+v %v", checkpoint, err)
			}
		})
		badHash := ref
		badHash.ContentHash = strings.Repeat("0", 64)
		if badHash.ContentHash == ref.ContentHash {
			badHash.ContentHash = strings.Repeat("1", 64)
		}
		badExecutionRevision := ref
		badExecutionRevision.ExecutionRevision++
		badExpiry := ref
		badExpiry.ExpiresAt = ref.ExpiresAt.Add(time.Hour)
		for name, altered := range map[string]contract.RecoveryCheckpointReference{
			"content hash": badHash, "execution revision": badExecutionRevision, "expiry": badExpiry,
		} {
			if checkpoint, err := store.LoadReference(ctx, scope, altered); !errors.Is(err, ErrStateConflict) || checkpoint.Value != nil {
				t.Fatalf("changed %s reference was accepted: %+v %v", name, checkpoint, err)
			}
		}
	})
	t.Run("actual-iam-disabled-principal-cannot-replay-state", func(t *testing.T) {
		iam := identity.NewSQLStore(db)
		if err := iam.EnsureSchema(ctx); err != nil {
			t.Fatal(err)
		}
		if err := iam.CreateTenant(ctx, identity.Tenant{ID: scope.TenantID, Code: scope.TenantID, Name: "isolated checkpoint IAM", Status: "active", Revision: 1}); err != nil {
			t.Fatal(err)
		}
		if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: scope.PrincipalID, TenantID: scope.TenantID, IsActive: true, Revision: 1}); err != nil {
			t.Fatal(err)
		}
		iam.SetPrincipalLifecycleRecorder(func(_ context.Context, tx *sql.Tx, actor sharedkernel.Scope, decision identity.PrincipalLifecycleDecision) error {
			return recorder.RecordTx(tx, audit.Event{ID: "checkpoint-iam-" + id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: "user", ActorID: actor.PrincipalID, TraceID: scope.TraceID, AggregateType: "principal", AggregateID: decision.PrincipalID, Action: "principal.disable", Outcome: "success", Summary: "isolated checkpoint principal disabled", CreatedAt: decision.OccurredAt})
		})
		actor := scope
		actor.PrincipalID = "checkpoint-operator"
		if _, err := iam.DisablePrincipal(ctx, actor, scope.PrincipalID, 1); err != nil {
			t.Fatal(err)
		}
		store.SetContinuityGuard(func(ctx context.Context, tx *sql.Tx, candidate sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding) error {
			if err := iam.AcquirePermissionReadContinuity(ctx, tx); err != nil {
				return err
			}
			return runs.CheckCheckpointLeaseTx(ctx, tx, candidate, lease)
		})
		defer store.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
		currentPrincipal := func(ctx context.Context) error {
			principal, err := iam.GetPrincipal(ctx, identity.PrincipalUser, scope.PrincipalID)
			if err != nil {
				return err
			}
			if !principal.IsActive {
				return identity.ErrPermissionDenied
			}
			return nil
		}
		attempt := write
		attempt.Lease.Revision++
		if _, err := store.Save(ctx, attempt, currentPrincipal); !errors.Is(err, ErrStateDenied) {
			t.Fatalf("real disabled IAM principal replayed a checkpoint: %v", err)
		}
	})
	t.Run("tamper-and-natural-expiry", func(t *testing.T) {
		_, key, _ := stateKeys(scope, write.Namespace, write.Key)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET value_json='{"tampered":true}' WHERE scope_key=? AND revision=1`), key); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 1); !errors.Is(err, ErrStateUnavailable) {
			t.Fatalf("corrupt checkpoint accepted: %v", err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_state_head SET expires_at=clock_timestamp()+INTERVAL '1 hour' WHERE scope_key=?`), key); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE scope_key=? AND revision=2`), key); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 2); found || !errors.Is(err, ErrStateContinuityLost) {
			t.Fatalf("expired historical checkpoint returned: found=%v err=%v", found, err)
		}
		if current, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0); err != nil || !found || current.Revision != 3 {
			t.Fatalf("expired history hid current checkpoint: %+v found=%v err=%v", current, found, err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE scope_key=? AND revision=3`), key); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0); found || !errors.Is(err, ErrStateContinuityLost) {
			t.Fatalf("expired latest payload with a live head returned: found=%v err=%v", found, err)
		}
		if refs, err := captureRecoverySnapshot(scope); !errors.Is(err, ErrStateContinuityLost) || len(refs) != 0 {
			t.Fatalf("snapshot accepted an expired latest payload: %#v %v", refs, err)
		}
		if checkpoint, err := store.LoadReference(ctx, scope, currentRecoveryReference); err == nil || checkpoint.Value != nil {
			t.Fatalf("LoadReference accepted an expired latest payload: %+v %v", checkpoint, err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_state_head SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE scope_key=?`), key); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0); found || !errors.Is(err, ErrStateContinuityLost) {
			t.Fatalf("expired state did not preserve lost continuity: found=%v err=%v", found, err)
		}
		attempt := write
		attempt.Lease.Revision++
		if _, err := store.Save(ctx, attempt, allowed); !errors.Is(err, ErrStateConflict) {
			t.Fatalf("replay ignored expired lineage head: %v", err)
		}
	})
	var checkpoints, audits int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_business_checkpoint WHERE scope_key=?`), func() string { _, key, _ := stateKeys(scope, write.Namespace, write.Key); return key }()).Scan(&checkpoints); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE trace_id=? AND action='state.checkpoint.save'`), scope.TraceID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if checkpoints != 3 || audits != 3 {
		t.Fatalf("state/audit exactly once mismatch: checkpoints=%d audits=%d", checkpoints, audits)
	}
	var notifications int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE event_type='audit.state.checkpoint.save' AND partition_key=?`), func() string { _, key, _ := stateKeys(scope, write.Namespace, write.Key); return key }()).Scan(&notifications); err != nil || notifications != 3 {
		t.Fatalf("checkpoint/audit/Outbox exactly-once mismatch: events=%d %v", notifications, err)
	}
	t.Run("expired-payload-pruning-preserves-lineage", func(t *testing.T) {
		_, key, _ := stateKeys(scope, write.Namespace, write.Key)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_business_checkpoint SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE scope_key=?`), key); err != nil {
			t.Fatal(err)
		}
		first, err := store.PruneExpired(ctx, 2)
		if err != nil || first != 2 {
			t.Fatalf("bounded first batch: %d %v", first, err)
		}
		second, err := store.PruneExpired(ctx, 2)
		if err != nil || second != 1 {
			t.Fatalf("bounded second batch: %d %v", second, err)
		}
		if _, found, err := store.Load(ctx, scope, write.Namespace, write.Key, write.SchemaID, 0); found || !errors.Is(err, ErrStateContinuityLost) {
			t.Fatalf("pruned lineage returned as absent: found=%v err=%v", found, err)
		}
		if refs, err := captureRecoverySnapshot(scope); !errors.Is(err, ErrStateContinuityLost) || len(refs) != 0 {
			t.Fatalf("snapshot accepted pruned lineage: %#v %v", refs, err)
		}
		if checkpoint, err := store.LoadReference(ctx, scope, currentRecoveryReference); err == nil || checkpoint.Value != nil {
			t.Fatalf("LoadReference accepted pruned lineage: %+v %v", checkpoint, err)
		}
		var headRevision int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_business_state_head WHERE scope_key=?`), key).Scan(&headRevision); err != nil || headRevision != 3 {
			t.Fatalf("cleanup reset lineage: %d %v", headRevision, err)
		}
		attempt := write
		attempt.Lease.Revision++
		attempt.IdempotencyKey = "after-expiry"
		if _, err := store.Save(ctx, attempt, allowed); !errors.Is(err, ErrStateConflict) {
			t.Fatalf("expired lineage recreated: %v", err)
		}
		for _, absent := range []struct{ namespace, key string }{
			{namespace: write.Namespace, key: "never-created"},
			{namespace: "never-created", key: "never-created"},
		} {
			if _, found, err := store.Load(ctx, scope, absent.namespace, absent.key, write.SchemaID, 0); err != nil || found {
				t.Fatalf("uncreated state was not absent (%s/%s): found=%v err=%v", absent.namespace, absent.key, found, err)
			}
		}
	})
}
