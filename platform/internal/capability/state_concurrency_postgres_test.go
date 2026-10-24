package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/notification"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Pause after checkpoint mutations, inside the actual SQL transaction. Two
// arrivals prove independent writers overlap, without timing a sleep or HTTP.
type checkpointAuditBarrier struct {
	ctx      context.Context
	delegate audit.TxRecorder
	arrived  chan struct{}
	release  <-chan struct{}
}

type checkpointAuditHook struct {
	delegate audit.TxRecorder
	after    func()
}

func (h checkpointAuditHook) RecordTx(tx *sql.Tx, event audit.Event) error {
	if err := h.delegate.RecordTx(tx, event); err != nil {
		return err
	}
	h.after()
	return nil
}

func (b checkpointAuditBarrier) RecordTx(tx *sql.Tx, event audit.Event) error {
	select {
	case b.arrived <- struct{}{}:
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
	select {
	case <-b.release:
		return b.delegate.RecordTx(tx, event)
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

func TestSQLCheckpointIndependentWritesRemainFenced(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("owned migration and DML-only runtime PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	owner, err := execution.ConnectSQLStore(ctx, "pgx", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := execution.MigrateSchema(ctx, owner.DB()); err != nil {
		t.Fatal(err)
	}
	outbox := notification.NewSQLStore(owner.DB())
	if err := outbox.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := audit.NewSQLStoreWithOutbox(owner.DB(), outbox).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	schemaStore, err := NewSQLCheckpointStore(owner.DB())
	if err != nil {
		t.Fatal(err)
	}
	if err := schemaStore.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	runs, err := execution.ConnectSQLStore(ctx, "pgx", runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runs.Close()
	db := runs.DB()
	recorder := audit.NewSQLStoreWithOutbox(db, notification.NewSQLStore(db))
	fixture := func(t *testing.T) (*SQLCheckpointStore, StateWrite) {
		t.Helper()
		id := fmt.Sprintf("parallel-checkpoint-%d", time.Now().UnixNano())
		scope := mcpTestScope()
		scope.RunID, scope.SessionID, scope.TraceID = id, id, id
		if _, err := runs.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "parallel-checkpoint"}); err != nil {
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
		store, err := NewSQLCheckpointStore(db)
		if err != nil {
			t.Fatal(err)
		}
		store.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
		store.SetAuditRecorder(recorder)
		return store, StateWrite{Scope: scope, Lease: sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}, Namespace: "harness", Key: "left", SchemaID: "schema://example/state/v1", IdempotencyKey: "initial", Value: map[string]any{"phase": "initial"}, TTLSeconds: 60, MaxEntries: 2}
	}
	allowed := func(context.Context) error { return nil }
	t.Run("current-authority-joins-resource-and-data-transactions", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		owners := map[*sql.Tx]int{}
		store.SetContinuityGuard(func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, lease sharedkernel.ExecutionLeaseBinding) error {
			bound, present, err := sqlutil.ContinuityTransaction(ctx, db)
			if err != nil || !present || bound != tx {
				return errors.New("checkpoint guard lost transaction owner")
			}
			owners[tx]++
			return runs.CheckCheckpointLeaseTx(ctx, tx, scope, lease)
		})
		check := func(ctx context.Context) error {
			tx, present, err := sqlutil.ContinuityTransaction(ctx, db)
			if err != nil || !present || owners[tx] == 0 {
				return errors.New("checkpoint callback escaped guarded transaction")
			}
			return tx.QueryRowContext(ctx, `SELECT 1`).Scan(new(int))
		}
		result, err := store.Save(ctx, write, check)
		if err != nil || result.Revision != 1 || len(owners) != 2 {
			t.Fatalf("resource/data owners: %d, result: %+v, err: %v", len(owners), result, err)
		}
		for tx := range owners {
			if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(new(int)); !errors.Is(err, sql.ErrTxDone) {
				t.Fatal("checkpoint owner left transaction open", err)
			}
		}
		write.ExpectedRevision, write.IdempotencyKey = 1, "denied-final"
		write.Value = map[string]any{"phase": "must-rollback"}
		checks := 0
		denied := errors.New("authority withdrawn before commit")
		_, err = store.Save(ctx, write, func(ctx context.Context) error {
			if err := check(ctx); err != nil {
				return err
			}
			checks++
			if checks == 2 {
				return denied
			}
			return nil
		})
		if !errors.Is(err, denied) {
			t.Fatal("final authority did not stop data commit", err)
		}
		prior, found, err := store.Load(ctx, write.Scope, write.Namespace, write.Key, write.SchemaID, 0)
		if err != nil || !found || prior.Revision != 1 || prior.Value["phase"] != "initial" {
			t.Fatal("denied write escaped rollback", prior, err)
		}
	})
	t.Run("legacy-new-head-holds-scope-quota-through-data-audit", func(t *testing.T) {
		store, write := fixture(t)
		pauseCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		release := make(chan struct{})
		defer close(release)
		barrier := checkpointAuditBarrier{ctx: pauseCtx, delegate: recorder, arrived: make(chan struct{}, 1), release: release}
		store.SetAuditRecorder(barrier)
		finished := make(chan error, 1)
		go func() { _, err := store.Save(pauseCtx, write, allowed); finished <- err }()
		select {
		case <-barrier.arrived:
		case <-pauseCtx.Done():
			t.Fatal("new head failed to reach audit")
		}
		prefix, _, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		digest := sha256.Sum256([]byte("business-state\x00" + prefix))
		lock := int64(binary.BigEndian.Uint64(digest[:8]))
		probe, err := db.BeginTx(pauseCtx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Rollback()
		var available bool
		if err = probe.QueryRowContext(pauseCtx, "SELECT pg_try_advisory_xact_lock_shared($1)", lock).Scan(&available); err != nil || available {
			t.Fatal("legacy scope lock not held through data/audit", available, err)
		}
		// Cancellation frees the paused data transaction without committing it.
		stop()
		if err := <-finished; err == nil {
			t.Fatal("cancelled characterization unexpectedly committed")
		}
	})
	t.Run("reserved-eight-new-heads-overlap-with-strict-quota", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		write.MaxEntries = 8
		pauseCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		release := make(chan struct{})
		barrier := checkpointAuditBarrier{ctx: pauseCtx, delegate: recorder, arrived: make(chan struct{}, 8), release: release}
		store.SetAuditRecorder(barrier)
		finished := make(chan error, 8)
		for i := 0; i < 8; i++ {
			attempt := write
			attempt.Key = fmt.Sprintf("new-%d", i)
			go func() { _, err := store.Save(pauseCtx, attempt, allowed); finished <- err }()
		}
		arrivals := 0
		for arrivals < 8 {
			select {
			case <-barrier.arrived:
				arrivals++
			case <-pauseCtx.Done():
				close(release)
				for range 8 {
					<-finished
				}
				t.Fatal("reserved data transactions serialized", arrivals)
			}
		}
		// All eight uncommitted data writers reached their real audit boundary.
		// Neither the opted-in nor the legacy branch may admit a ninth head.
		for _, reserved := range []bool{true, false} {
			extra := write
			extra.Key = "overflow"
			extra.ReservedQuota = reserved
			if _, err := store.Save(pauseCtx, extra, allowed); !errors.Is(err, ErrStateLimit) {
				close(release)
				for range 8 {
					<-finished
				}
				t.Fatal("quota bypass", reserved, err)
			}
		}
		close(release)
		for range 8 {
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		}
		prefix, _, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		var count, uncovered int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_business_state_admission WHERE scope_prefix=$1", prefix).Scan(&count); err != nil || count != 8 {
			t.Fatal("quota identities", count, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM platform_business_state_head h JOIN platform_business_state_admission a USING(scope_key) WHERE h.scope_prefix=$1 AND h.expires_at>a.expires_at`, prefix).Scan(&uncovered); err != nil || uncovered != 0 {
			t.Fatal("committed head outlives quota lease", uncovered, err)
		}
	})
	t.Run("reserved-new-head-and-independent-update-overlap", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		if _, err := store.Save(ctx, write, allowed); err != nil {
			t.Fatal(err)
		}
		pauseCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		release := make(chan struct{})
		barrier := checkpointAuditBarrier{ctx: pauseCtx, delegate: recorder, arrived: make(chan struct{}, 2), release: release}
		store.SetAuditRecorder(barrier)
		finished := make(chan error, 2)
		update := write
		update.ExpectedRevision = 1
		update.IdempotencyKey = "update"
		fresh := write
		fresh.Key = "right"
		for _, attempt := range []StateWrite{update, fresh} {
			go func() { _, err := store.Save(pauseCtx, attempt, allowed); finished <- err }()
		}
		for i := 0; i < 2; i++ {
			select {
			case <-barrier.arrived:
			case <-pauseCtx.Done():
				close(release)
				for range 2 {
					<-finished
				}
				t.Fatal("mixed writer blocked on quota")
			}
		}
		close(release)
		for range 2 {
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("reserved-rollback-reopen-and-schema-correction-reuse-one-slot", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		write.MaxEntries = 1
		written := false
		store.SetAuditRecorder(checkpointAuditHook{delegate: recorder, after: func() { written = true }})
		denied := func(context.Context) error {
			if written {
				return ErrStateDenied
			}
			return nil
		}
		wrong := write
		wrong.SchemaID = "schema://example/uncommitted/v1"
		if _, err := store.Save(ctx, wrong, denied); !errors.Is(err, ErrStateDenied) {
			t.Fatal("post-write revocation not rolled back", err)
		}
		if _, found, err := store.Load(ctx, write.Scope, write.Namespace, write.Key, write.SchemaID, 0); err != nil || found {
			t.Fatal("quota reservation became business State", found, err)
		}
		reopened, err := NewSQLCheckpointStore(db)
		if err != nil {
			t.Fatal(err)
		}
		reopened.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
		reopened.SetAuditRecorder(recorder)
		if _, err := reopened.Save(ctx, write, allowed); err != nil {
			t.Fatal("uncommitted Schema poisoned quota identity", err)
		}
		extra := write
		extra.Key = "extra"
		if _, err := reopened.Save(ctx, extra, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatal("quota retry added a slot", err)
		}
		_, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		var audits int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_audit_event WHERE aggregate_type='business_checkpoint' AND aggregate_id=$1", id).Scan(&audits); err != nil || audits != 1 {
			t.Fatal("rolled-back audit leaked", audits, err)
		}
	})
	t.Run("valid-reservation-reuse-does-not-wait-on-scope-quota-mutex", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		if _, err := store.Save(ctx, write, allowed); err != nil {
			t.Fatal(err)
		}
		prefix, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		var before, after time.Time
		if err := db.QueryRowContext(ctx, "SELECT updated_at FROM platform_business_state_admission WHERE scope_key=$1", id).Scan(&before); err != nil {
			t.Fatal(err)
		}
		mutex, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer mutex.Rollback()
		if err := lockLedgerScope(ctx, mutex, "business-state", prefix); err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		write.ExpectedRevision, write.IdempotencyKey = 1, "reuse"
		if value, err := store.Save(bounded, write, allowed); err != nil || value.Revision != 2 {
			t.Fatal("existing reservation blocked behind scope quota mutex", value.Revision, err)
		}
		if err := db.QueryRowContext(ctx, "SELECT updated_at FROM platform_business_state_admission WHERE scope_key=$1", id).Scan(&after); err != nil || !before.Equal(after) {
			t.Fatal("reuse unexpectedly renewed resource slot", before, after, err)
		}
	})
	t.Run("reuse-refreshes-insufficient-coverage-and-respects-lower-quota", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota, write.MaxEntries = true, 2
		if _, err := store.Save(ctx, write, allowed); err != nil {
			t.Fatal(err)
		}
		_, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		if _, err := owner.DB().ExecContext(ctx, "UPDATE platform_business_state_admission SET expires_at=clock_timestamp()+interval '1 second' WHERE scope_key=$1", id); err != nil {
			t.Fatal(err)
		}
		write.ExpectedRevision, write.IdempotencyKey = 1, "refresh"
		if _, err := store.Save(ctx, write, allowed); err != nil {
			t.Fatal("short reservation was not refreshed", err)
		}
		var covered bool
		if err := db.QueryRowContext(ctx, "SELECT a.expires_at>=h.expires_at FROM platform_business_state_admission a JOIN platform_business_state_head h USING(scope_key) WHERE a.scope_key=$1", id).Scan(&covered); err != nil || !covered {
			t.Fatal("refreshed checkpoint TTL uncovered", covered, err)
		}
		other := write
		other.Key, other.ExpectedRevision, other.IdempotencyKey = "other", 0, "first"
		if _, err := store.Save(ctx, other, allowed); err != nil {
			t.Fatal(err)
		}
		write.MaxEntries, write.ExpectedRevision, write.IdempotencyKey = 1, 2, "lower-limit"
		if _, err := store.Save(ctx, write, allowed); !errors.Is(err, ErrStateLimit) {
			t.Fatal("reuse bypassed current lower quota", err)
		}
		write.MaxEntries = 2
		write.Lease.TokenHash = fmt.Sprintf("%064d", 0)
		if _, err := store.Save(ctx, write, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatal("reused capacity conferred execution authority", err)
		}
	})
	t.Run("reserved-stale-lease-cannot-reserve-or-save", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		write.Lease.TokenHash = fmt.Sprintf("%064d", 0)
		if _, err := store.Save(ctx, write, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatal("invalid lease admitted", err)
		}
		prefix, _, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_business_state_admission WHERE scope_prefix=$1", prefix).Scan(&count); err != nil || count != 0 {
			t.Fatal("stale lease consumed quota", count, err)
		}
	})
	t.Run("different-existing-heads-overlap-before-commit", func(t *testing.T) {
		store, write := fixture(t)
		for _, key := range []string{"left", "right"} {
			seed := write
			seed.Key = key
			if _, err := store.Save(ctx, seed, allowed); err != nil {
				t.Fatal(err)
			}
		}
		barrierCtx, barrierCancel := context.WithTimeout(ctx, 5*time.Second)
		defer barrierCancel()
		release := make(chan struct{})
		barrier := checkpointAuditBarrier{ctx: barrierCtx, delegate: recorder, arrived: make(chan struct{}, 2), release: release}
		store.SetAuditRecorder(barrier)
		results := make(chan error, 2)
		for _, key := range []string{"left", "right"} {
			attempt := write
			attempt.Key, attempt.ExpectedRevision, attempt.IdempotencyKey = key, 1, "updated"
			go func() { _, err := store.Save(barrierCtx, attempt, allowed); results <- err }()
		}
		arrivals := 0
		for arrivals < 2 {
			select {
			case <-barrier.arrived:
				arrivals++
			case <-barrierCtx.Done():
				close(release)
				for i := 0; i < 2; i++ {
					<-results
				}
				t.Fatalf("independent checkpoint writes serialized: arrivals=%d: %v", arrivals, barrierCtx.Err())
			}
		}
		close(release)
		for i := 0; i < 2; i++ {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		for _, key := range []string{"left", "right"} {
			head, found, err := store.Load(ctx, write.Scope, write.Namespace, key, write.SchemaID, 0)
			if err != nil || !found || head.Revision != 2 {
				t.Fatalf("committed %s: %+v %v %v", key, head, found, err)
			}
		}
	})
	for _, reserved := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-head-identical-retries-share-one-result-and-audit-reserved-%t", reserved), func(t *testing.T) {
			store, write := fixture(t)
			write.ReservedQuota = reserved
			if _, err := store.Save(ctx, write, allowed); err != nil {
				t.Fatal(err)
			}
			write.ExpectedRevision, write.IdempotencyKey, write.Value = 1, "retry", map[string]any{"phase": "updated"}
			type result struct {
				checkpoint Checkpoint
				err        error
			}
			results := make(chan result, 8)
			for i := 0; i < 8; i++ {
				go func() { checkpoint, err := store.Save(ctx, write, allowed); results <- result{checkpoint, err} }()
			}
			var first Checkpoint
			for i := 0; i < 8; i++ {
				got := <-results
				if got.err != nil || got.checkpoint.Revision != 2 {
					t.Fatalf("identical retry: %+v %v", got.checkpoint, got.err)
				}
				if i == 0 {
					first = got.checkpoint
				} else if first.ContentHash != got.checkpoint.ContentHash || !first.ExpiresAt.Equal(got.checkpoint.ExpiresAt) {
					t.Fatal("identical retry changed committed result")
				}
			}
			_, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
			var count int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE aggregate_type='business_checkpoint' AND aggregate_id=?`), id).Scan(&count); err != nil || count != 2 {
				t.Fatalf("seed plus exactly one update audit: count=%d err=%v", count, err)
			}
		})
	}
	t.Run("reservation-acknowledgement-lost-reopen-with-either-policy", func(t *testing.T) {
		for _, reserved := range []bool{false, true} {
			store, write := fixture(t)
			write.MaxEntries = 1
			prefix, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
			// A committed reservation whose response was lost is only capacity.
			if err := store.reserveCheckpointQuota(ctx, write, prefix, id, allowed); err != nil {
				t.Fatal(err)
			}
			if _, found, err := store.Load(ctx, write.Scope, write.Namespace, write.Key, write.SchemaID, 0); err != nil || found {
				t.Fatal("reservation disclosed as checkpoint", found, err)
			}
			reopened, _ := NewSQLCheckpointStore(db)
			reopened.SetContinuityGuard(runs.CheckCheckpointLeaseTx)
			reopened.SetAuditRecorder(recorder)
			write.ReservedQuota = reserved
			if value, err := reopened.Save(ctx, write, allowed); err != nil || value.Revision != 1 {
				t.Fatal("own reserved identity counted twice", reserved, value.Revision, err)
			}
		}
	})
	t.Run("reservation-must-cover-checkpoint-ttl-before-writing", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		_, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		checks := 0
		shorten := func(context.Context) error {
			checks++
			if checks == 2 {
				_, err := owner.DB().ExecContext(ctx, "UPDATE platform_business_state_admission SET expires_at=clock_timestamp()+interval '1 second' WHERE scope_key=$1", id)
				return err
			}
			return nil
		}
		// Shorten at the first data check, before the store reads its proof.
		// There is no wait/sleep and no provider or business write in this fault.
		if _, err := store.Save(ctx, write, shorten); !errors.Is(err, ErrStateLimit) {
			t.Fatal("checkpoint outlived reservation", err)
		}
		if _, found, err := store.Load(ctx, write.Scope, write.Namespace, write.Key, write.SchemaID, 0); err != nil || found {
			t.Fatal("uncovered checkpoint persisted", found, err)
		}
	})
	t.Run("cancel-after-reservation-invalidates-data-authority", func(t *testing.T) {
		store, write := fixture(t)
		write.ReservedQuota = true
		prefix, id, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		if err := store.reserveCheckpointQuota(ctx, write, prefix, id, allowed); err != nil {
			t.Fatal(err)
		}
		if _, err := runs.Cancel(write.Scope.RunID, write.Lease.Revision); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Save(ctx, write, allowed); !errors.Is(err, ErrStateDenied) {
			t.Fatal("reservation conferred authority after cancellation", err)
		}
		var heads, reservations int
		if err := db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM platform_business_state_head WHERE scope_key=$1),(SELECT count(*) FROM platform_business_state_admission WHERE scope_key=$1)", id).Scan(&heads, &reservations); err != nil || heads != 0 || reservations != 1 {
			t.Fatal("cancelled save committed data or erased conservative reservation", heads, reservations, err)
		}
	})
	t.Run("expired-reservations-pruned-in-bounded-batches-without-state", func(t *testing.T) {
		store, write := fixture(t)
		write.MaxEntries = 3
		prefix, _, _ := stateKeys(write.Scope, write.Namespace, write.Key)
		for _, key := range []string{"expired-one", "expired-two", "active"} {
			attempt := write
			attempt.Key = key
			_, id, _ := stateKeys(write.Scope, write.Namespace, key)
			if err := store.reserveCheckpointQuota(ctx, attempt, prefix, id, allowed); err != nil {
				t.Fatal(err)
			}
			if key != "active" {
				if _, err := owner.DB().ExecContext(ctx, "UPDATE platform_business_state_admission SET expires_at=clock_timestamp()-interval '1 second' WHERE scope_key=$1", id); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, want := range []int{2, 1} {
			if payloads, err := store.PruneExpired(ctx, 1); err != nil || payloads != 0 {
				t.Fatal("reservation became checkpoint payload", payloads, err)
			}
			var count int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM platform_business_state_admission WHERE scope_prefix=$1", prefix).Scan(&count); err != nil || count != want {
				t.Fatal("reservation pruning unbounded or active admission removed", count, want, err)
			}
		}
		write.Key = "active"
		write.ReservedQuota = true
		if _, err := store.Save(ctx, write, allowed); err != nil {
			t.Fatal("maintenance broke active reservation", err)
		}
	})
	t.Run("new-heads-enforce-shared-scope-quota", func(t *testing.T) {
		store, write := fixture(t)
		results := make(chan error, 3)
		for _, key := range []string{"one", "two", "three"} {
			attempt := write
			attempt.Key = key
			go func() { _, err := store.Save(ctx, attempt, allowed); results <- err }()
		}
		var succeeded, limited int
		for i := 0; i < 3; i++ {
			err := <-results
			if err == nil {
				succeeded++
			} else if errors.Is(err, ErrStateLimit) {
				limited++
			} else {
				t.Fatal(err)
			}
		}
		if succeeded != 2 || limited != 1 {
			t.Fatalf("quota: success=%d limit=%d", succeeded, limited)
		}
	})
}
