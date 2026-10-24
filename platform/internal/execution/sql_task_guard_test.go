package execution

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLTaskCheckpointLeaseTransactionFence(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := openMigratedSQLFixture(ctx, "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := fmt.Sprintf("task-checkpoint-%d", time.Now().UnixNano())
	scope := testScope(id).domain()
	scope.SessionID = id
	_, err = store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(id, "task-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	check := func(candidate sharedkernel.Scope, token string, revision uint64, want error) {
		t.Helper()
		tx, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := store.CheckTaskLeaseTx(ctx, tx, candidate, token, revision); !errors.Is(err, want) {
			t.Fatalf("task fence: got %v, want %v", err, want)
		}
		hash := sha256.Sum256([]byte(token))
		binding := sharedkernel.ExecutionLeaseBinding{Revision: revision, TokenHash: fmt.Sprintf("%x", hash)}
		if err := store.CheckCapabilityLeaseTx(ctx, tx, candidate, binding); !errors.Is(err, want) {
			t.Fatalf("signed capability fence: got %v, want %v", err, want)
		}
		if err := store.CheckCheckpointLeaseTx(ctx, tx, candidate, binding); !errors.Is(err, want) {
			t.Fatalf("checkpoint shared fence: got %v, want %v", err, want)
		}
		if err := store.CheckCapabilityReadLeaseTx(ctx, tx, candidate, binding); !errors.Is(err, want) {
			t.Fatalf("capability read fence: got %v, want %v", err, want)
		}
	}
	check(scope, run.LeaseToken, run.Revision, nil)
	for _, mutate := range []func(*sharedkernel.Scope){
		func(s *sharedkernel.Scope) { s.TenantID += "-foreign" },
		func(s *sharedkernel.Scope) { s.DepartmentID += "-foreign" },
		func(s *sharedkernel.Scope) { s.ApplicationID += "-foreign" },
		func(s *sharedkernel.Scope) { s.PrincipalID += "-foreign" },
		func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" },
		func(s *sharedkernel.Scope) { s.AgentID += "-foreign" },
		func(s *sharedkernel.Scope) { s.AgentInstanceID += "-foreign" },
		func(s *sharedkernel.Scope) { s.InstallationID += "-foreign" },
		func(s *sharedkernel.Scope) { s.AgentVersionID += "-foreign" },
		func(s *sharedkernel.Scope) { s.SessionID += "-foreign" },
		func(s *sharedkernel.Scope) { s.RunID += "-foreign" },
		func(s *sharedkernel.Scope) { s.TraceID += "-foreign" },
		func(s *sharedkernel.Scope) { s.ParentRunID = "foreign-parent" },
		func(s *sharedkernel.Scope) { s.AuthorizationEpoch++ },
	} {
		foreign := scope
		mutate(&foreign)
		check(foreign, run.LeaseToken, run.Revision, platformruntime.ErrLeaseConflict)
	}
	check(scope, "foreign-token", run.Revision, platformruntime.ErrLeaseConflict)
	check(scope, run.LeaseToken, run.Revision+1, platformruntime.ErrLeaseConflict)
	if err := store.CheckTaskLeaseTx(ctx, nil, scope, run.LeaseToken, run.Revision); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("nil transaction accepted")
	}
	alterThenReject := func(query string, args ...any) {
		t.Helper()
		tx, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(query), args...); err != nil {
			t.Fatal(err)
		}
		if err := store.CheckTaskLeaseTx(ctx, tx, scope, run.LeaseToken, run.Revision); !errors.Is(err, platformruntime.ErrLeaseConflict) {
			t.Fatalf("invalid lease state accepted: %v", err)
		}
		hash := sha256.Sum256([]byte(run.LeaseToken))
		if err := store.CheckCapabilityLeaseTx(ctx, tx, scope, sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}); !errors.Is(err, platformruntime.ErrLeaseConflict) {
			t.Fatalf("invalid signed capability state accepted: %v", err)
		}
		if err := store.CheckCheckpointLeaseTx(ctx, tx, scope, sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}); !errors.Is(err, platformruntime.ErrLeaseConflict) {
			t.Fatalf("invalid shared checkpoint lease accepted: %v", err)
		}
	}
	alterThenReject(`UPDATE platform_execution_run SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=?`, id)
	alterThenReject(`UPDATE platform_execution_session_lease SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE run_id=?`, id)
	alterThenReject(`UPDATE platform_execution_session_lease SET lease_token='foreign' WHERE run_id=?`, id)
	alterThenReject(`DELETE FROM platform_execution_session_lease WHERE run_id=?`, id)
	for _, status := range []string{"accepted", "waiting", "cancelling", "recovering", "succeeded", "failed", "cancelled"} {
		alterThenReject(`UPDATE platform_execution_run SET status=? WHERE run_id=?`, status, id)
	}
	// Both guards hold row locks across the following task write, not just
	// during the validation call. NOWAIT gives deterministic conflict evidence.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckTaskLeaseTx(ctx, tx, scope, run.LeaseToken, run.Revision); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	for _, table := range []string{"platform_execution_run", "platform_execution_session_lease"} {
		other, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var value string
		err = other.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id FROM `+table+` WHERE run_id=? FOR UPDATE NOWAIT`), id).Scan(&value)
		other.Rollback()
		var state interface{ SQLState() string }
		if !errors.As(err, &state) || state.SQLState() != "55P03" {
			tx.Rollback()
			t.Fatalf("%s not transaction fenced: %v", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Independent checkpoint writers share execution fences, while lifecycle
	// mutation still requires an exclusive lock until both writers finish.
	left, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Rollback()
	right, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Rollback()
	hash := sha256.Sum256([]byte(run.LeaseToken))
	binding := sharedkernel.ExecutionLeaseBinding{Revision: run.Revision, TokenHash: fmt.Sprintf("%x", hash)}
	if err := store.CheckCheckpointLeaseTx(ctx, left, scope, binding); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckCapabilityReadLeaseTx(ctx, right, scope, binding); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"platform_execution_run", "platform_execution_session_lease"} {
		other, err := store.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var value string
		err = other.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id FROM `+table+` WHERE run_id=? FOR UPDATE NOWAIT`), id).Scan(&value)
		other.Rollback()
		var state interface{ SQLState() string }
		if !errors.As(err, &state) || state.SQLState() != "55P03" {
			t.Fatalf("%s not fenced by shared checkpoint writers: %v", table, err)
		}
	}
	if err := left.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := right.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginCancellation(id, run.Revision); err != nil {
		t.Fatal(err)
	}
	check(scope, run.LeaseToken, run.Revision, platformruntime.ErrLeaseConflict)
}
