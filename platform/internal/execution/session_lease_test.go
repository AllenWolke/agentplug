package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func exerciseSessionLease(t *testing.T, store Repository) {
	t.Helper()
	prefix := fmt.Sprintf("session-audit-%d", time.Now().UnixNano())
	scope := testScope(prefix).domain()
	scope.SessionID = prefix
	create := func(id string, scope sharedkernel.Scope) platformruntime.Run {
		t.Helper()
		scope.RunID = id
		result, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: "test"})
		if err != nil {
			t.Fatal(err)
		}
		return result.Run
	}
	first := create(prefix+"-first", scope)
	next := create(prefix+"-next", scope)
	if _, err := store.AcquireLease(next.ID, "next-owner", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("FIFO bypass: %v", err)
	}
	var winners atomic.Int32
	var selected platformruntime.Run
	var mu sync.Mutex
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			run, err := store.AcquireLease(first.ID, fmt.Sprintf("owner-%d", index), time.Now().UTC(), time.Minute)
			if err == nil {
				winners.Add(1)
				mu.Lock()
				selected = run
				mu.Unlock()
			} else if !errors.Is(err, platformruntime.ErrLeaseConflict) {
				t.Errorf("claim error: %v", err)
			}
		}(i)
	}
	group.Wait()
	if winners.Load() != 1 {
		t.Fatalf("claim winners=%d", winners.Load())
	}
	running, err := store.TransitionLeased(first.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, selected.Revision, selected.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	// Every persistent namespace dimension is independently concurrent.
	// 每个持久化身份维度变化都必须获得独立会话锁，不能串线或错误阻塞。
	variants := []func(*sharedkernel.Scope){
		func(s *sharedkernel.Scope) { s.TenantID += "-other" }, func(s *sharedkernel.Scope) { s.DepartmentID += "-other" },
		func(s *sharedkernel.Scope) { s.ApplicationID += "-other" }, func(s *sharedkernel.Scope) { s.InstallationID += "-other" },
		func(s *sharedkernel.Scope) { s.AgentInstanceID += "-other" }, func(s *sharedkernel.Scope) { s.AgentID += "-other" },
		func(s *sharedkernel.Scope) { s.PrincipalID += "-other" }, func(s *sharedkernel.Scope) { s.PrincipalType = "service_principal" },
		func(s *sharedkernel.Scope) { s.SessionID += "-other" }, func(s *sharedkernel.Scope) { s.AgentVersionID += "-other" },
	}
	for i, mutate := range variants {
		otherScope := scope
		mutate(&otherScope)
		other := create(fmt.Sprintf("%s-independent-%d", prefix, i), otherScope)
		claimed, err := store.AcquireLease(other.ID, "independent-owner", time.Now().UTC(), time.Minute)
		if err != nil {
			t.Fatalf("dimension %d blocked: %v", i, err)
		}
		if _, err := store.Cancel(other.ID, claimed.Revision); err != nil {
			t.Fatal(err)
		}
	}
	waiting, err := store.TransitionLeased(first.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision, running.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(next.ID, "next-owner", time.Now().UTC().Add(2*time.Minute), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("waiting checkpoint overwritten: %v", err)
	}
	if err := store.CheckSessionLease(waiting, time.Now().UTC()); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("waiting has executable lease")
	}
	resumed, err := store.PrepareResume(first.ID, []byte(`{"decision":"approve"}`))
	if err != nil {
		t.Fatal(err)
	}
	reclaimed, err := store.AcquireLease(resumed.ID, "resume-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Heartbeat(first.ID, running.LeaseToken, running.Revision, time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("old owner renewed resumed Run")
	}
	if _, err := store.Heartbeat(first.ID, reclaimed.LeaseToken, reclaimed.Revision, time.Now().UTC(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionLeased(first.ID, platformruntime.StatusRunning, platformruntime.StatusSucceeded, reclaimed.Revision, reclaimed.LeaseToken); err != nil {
		t.Fatal(err)
	}
	claimedNext, err := store.AcquireLease(next.ID, "next-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal("finished Run did not release next session execution", err)
	}
	if err := store.CheckSessionLease(reclaimed, time.Now().UTC()); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("old Run retains session execution")
	}
	if _, err := store.Cancel(next.ID, claimedNext.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentSessionLeaseMemoryOrdering(t *testing.T) {
	exerciseSessionLease(t, platformruntime.NewStore())
}

func TestPersistentSessionLeaseSQLOrdering(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	exerciseSessionLease(t, store)
}

// An SQL-backed long-running command must renew its lease while blocked, then
// stop on a real database renewal fault before accepting further side effects.
// SQL 长任务阻塞期间持续续租，真实数据库故障后停止，旧世代不得写终态。
func TestSQLDispatcherHeartbeatStopsAfterDatabaseRenewalFault(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id := fmt.Sprintf("sql-heartbeat-stop-%d", time.Now().UnixNano())
	scope := testScope(id).domain()
	scope.SessionID = id
	created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ttl := 600 * time.Millisecond
	claimed, err := store.AcquireLease(created.Run.ID, "heartbeat-owner", time.Now().UTC(), ttl)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := NewDispatcher(store, "secret", 1)
	stop := d.startHeartbeat(ctx, cancel, running, ttl)
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := store.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if current.LeaseUntil.After(running.LeaseUntil.Add(350 * time.Millisecond)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("long SQL command did not renew lease")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := store.db.Exec(sqlutil.Bind(`CREATE FUNCTION fail_dispatcher_heartbeat_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'injected heartbeat failure' USING ERRCODE='P0001'; RETURN NEW; END $fault$; CREATE TRIGGER fail_dispatcher_heartbeat BEFORE UPDATE ON platform_execution_session_lease FOR EACH ROW EXECUTE FUNCTION fail_dispatcher_heartbeat_fn()`)); err != nil {
		t.Fatal(err)
	}
	defer store.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS fail_dispatcher_heartbeat ON platform_execution_session_lease; DROP FUNCTION IF EXISTS fail_dispatcher_heartbeat_fn()`))
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("renewal fault did not cancel the running dispatch")
	}
	stop()
	current, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if wait := time.Until(current.LeaseUntil.Add(25 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if _, err := store.FinalizeLeased(id, platformruntime.StatusSucceeded, current.Revision, running.LeaseToken, map[string]any{"unsafe": true}, nil); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("old owner finalized after lost renewal: %v", err)
	}
	if _, err := store.AcquireLease(id, "replacement", time.Now().UTC(), ttl); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("new owner bypassed stop-confirmation barrier: %v", err)
	}
}

func TestPersistentSessionLeaseSQLRestartAndHeartbeatRollback(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration fixture not configured")
	}
	store, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prefix := fmt.Sprintf("restart-session-%d", time.Now().UnixNano())
	scope := testScope(prefix).domain()
	scope.SessionID = prefix
	command := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		Operation:       "run",
		IdempotencyKey:  prefix,
		InputSchema:     KnowledgeIndexInputSchema,
		Scope: contract.ScopeKey{
			TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, InstallationID: scope.InstallationID,
			SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID,
		},
		Input: map[string]any{"knowledge_id": "session-lease-fixture"},
	}
	requestJSON, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateInternalTaskTx(context.Background(), tx, platformruntime.CreateRequest{ID: prefix, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: prefix, Fingerprint: fingerprint, RequestJSON: requestJSON})
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(first.Run.ID, "pre-crash-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	key := platformruntime.SessionExecutionKey(scope)
	// A failing session renewal must roll back the Run renewal in the same transaction.
	// 会话锁续租失败时 Run 续租必须回滚，不能产生一半有效的租约。
	if _, err := store.db.Exec(sqlutil.Bind(`CREATE FUNCTION fail_session_heartbeat_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'injected session heartbeat failure' USING ERRCODE='P0001'; RETURN NEW; END $fault$; CREATE TRIGGER fail_session_heartbeat BEFORE UPDATE ON platform_execution_session_lease FOR EACH ROW EXECUTE FUNCTION fail_session_heartbeat_fn()`)); err != nil {
		t.Fatal(err)
	}
	defer store.db.Exec(sqlutil.Bind(`DROP TRIGGER IF EXISTS fail_session_heartbeat ON platform_execution_session_lease; DROP FUNCTION IF EXISTS fail_session_heartbeat_fn()`))
	if _, err := store.Heartbeat(running.ID, running.LeaseToken, running.Revision, time.Now().UTC(), 3*time.Minute); err == nil {
		t.Fatal("session renewal failure hidden")
	}
	unchanged, err := store.Get(running.ID)
	if err != nil || !unchanged.LeaseUntil.Equal(running.LeaseUntil) {
		t.Fatalf("Run renewal not rolled back: %v", err)
	}
	if _, err := store.db.Exec(sqlutil.Bind(`DROP TRIGGER fail_session_heartbeat ON platform_execution_session_lease; DROP FUNCTION IF EXISTS fail_session_heartbeat_fn()`)); err != nil {
		t.Fatal(err)
	}
	// Expire only this fixture's owner; no production rows or database volumes touched.
	// 仅让本测试的租约过期，不改现有服务数据。
	past := time.Now().UTC().Add(-time.Second)
	if _, err := store.db.Exec(sqlutil.Bind(`UPDATE platform_execution_run SET lease_until=? WHERE run_id=?`), past, running.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_until=? WHERE session_key=?`), past, key); err != nil {
		t.Fatal(err)
	}
	restarted, err := openMigratedSQLFixture(context.Background(), "pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	nextScope := scope
	nextScope.RunID = prefix + "-next"
	next, err := restarted.Create(platformruntime.CreateRequest{ID: nextScope.RunID, Scope: nextScope, AgentVersionID: "v1", IdempotencyKey: nextScope.RunID, Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.AcquireLease(next.Run.ID, "foreign-run", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("expiry let another Run overwrite interrupted checkpoint", err)
	}
	// Expiry alone is not evidence that the previous remote execution stopped.
	// 过期不能证明远端已停止，先验证禁止抢占，再模拟已确认停止的持久化屏障。
	if _, err := restarted.AcquireLease(running.ID, "post-crash-owner", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("expired original Run was stolen without stop acknowledgement", err)
	}
	pending, err := restarted.BeginRecovery(running.ID, running.Revision, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// Model the internal index-task owner returning after its Execute function
	// has stopped. Recovery may complete only after that owner records its
	// lease-bound stop receipt; expiry alone is deliberately insufficient.
	// 模拟内部索引任务执行函数已返回，由原租约所有者写入停止回执后才允许恢复。
	if err := restarted.RecordInternalTaskStopped(context.Background(), running.Scope, running.LeaseToken, running.Revision); err != nil {
		t.Fatal("persist internal task stop receipt", err)
	}
	if _, err := restarted.CompleteRecovery(running.ID, pending.Revision); err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.AcquireLease(running.ID, "post-crash-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.CheckSessionLease(recovered, time.Now().UTC()); err != nil {
		t.Fatal("session recovery unavailable", err)
	}
	if err := restarted.CheckSessionLease(running, time.Now().UTC()); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("stale owner retained session", err)
	}
	if _, err := store.Heartbeat(running.ID, running.LeaseToken, running.Revision, time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("stale owner renewed", err)
	}
	if _, err := restarted.Cancel(recovered.ID, recovered.Revision); err != nil {
		t.Fatal(err)
	}
	nextClaim, err := restarted.AcquireLease(next.Run.ID, "next-owner", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal("cancellation did not release session", err)
	}
	if _, err := restarted.Cancel(nextClaim.ID, nextClaim.Revision); err != nil {
		t.Fatal(err)
	}
}
