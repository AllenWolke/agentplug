package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/sqlutil"
)

// TestEvaluationLeasePostgresIntegration checks durable ownership across workers.
// 验证真实数据库中的租约接管、过期执行者隔离和取消后的终态保护。
func TestEvaluationLeasePostgresIntegration(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires the isolated Compose PostgreSQL database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated PostgreSQL DSN")
	}
	admin, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	// Separate database prevents the running platform worker claiming fixtures.
	// 独立数据库防止运行中的平台 Worker 抢占本测试的待执行记录。
	database := fmt.Sprintf("eval_lease_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(sqlutil.Bind("CREATE DATABASE " + database)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(sqlutil.Bind("DROP DATABASE " + database)); err != nil {
			t.Errorf("cleanup test database: %v", err)
		}
	}()
	config.Database = database
	db := stdlib.OpenDB(*config)
	err = db.PingContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: fmt.Sprintf("eval-lease-%d", time.Now().UnixNano()), DepartmentID: "dept", ApplicationID: "app"}
	defer func() {
		for _, table := range []string{"platform_evaluation_product_run_lease", "platform_evaluation_product_version", "platform_evaluation_product_head"} {
			if _, err := db.ExecContext(context.Background(), sqlutil.Bind("DELETE FROM "+table+" WHERE tenant_id=?"), scope.TenantID); err != nil {
				t.Errorf("cleanup %s: %v", table, err)
			}
		}
	}()
	now := time.Now().UTC()
	data, _ := json.Marshal(RunData{SuiteID: "suite-lease", IdempotencyKey: "idem-lease", ExecutionState: "dispatch_pending"})
	run := Resource{ID: "run-lease", Kind: KindRun, Scope: scope, Status: "queued", Revision: 1, CreatedBy: "alice", CreatedAt: now, UpdatedAt: now, Data: data}
	if err := store.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	queue, err := store.QueueSnapshot(ctx)
	delta := queue.OldestQueuedAt.Sub(now)
	if err != nil || queue.Depth != 1 || delta < -time.Microsecond || delta > time.Microsecond {
		t.Fatalf("durable queue did not include queued run: %+v expected=%s delta=%s err=%v", queue, now.Format(time.RFC3339Nano), delta, err)
	}
	old, ok, err := store.ClaimNextRun(ctx, "worker-old", "token-old", now.Add(-time.Minute), time.Second)
	if err != nil || !ok || old.Scope != scope {
		t.Fatalf("old claim: ok=%v err=%v scope=%+v", ok, err, old.Scope)
	}
	queue, err = store.QueueSnapshot(ctx)
	if err != nil || queue.Depth != 0 || !queue.OldestQueuedAt.IsZero() {
		t.Fatalf("claimed run remained in durable queue: %+v err=%v", queue, err)
	}
	current, ok, err := store.ClaimNextRun(ctx, "worker-new", "token-new", now, time.Minute)
	if err != nil || !ok || current.ID != run.ID || current.Revision <= old.Revision {
		t.Fatalf("takeover: ok=%v err=%v row=%+v", ok, err, current)
	}
	var currentData RunData
	if err := json.Unmarshal(current.Data, &currentData); err != nil {
		t.Fatalf("decode current Evaluation lease: %v", err)
	}
	leaseTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CheckRunLeaseTx(ctx, leaseTx, scope, run.ID, currentData.LeaseOwner, currentData.LeaseToken, currentData.LeaseUntil, time.Now().UTC()); err != nil {
		_ = leaseTx.Rollback()
		t.Fatalf("exact head and durable Evaluation lease did not match: %v", err)
	}
	if err := store.CheckRunLeaseTx(ctx, leaseTx, scope, run.ID, "foreign-worker", currentData.LeaseToken, currentData.LeaseUntil, time.Now().UTC()); err == nil {
		_ = leaseTx.Rollback()
		t.Fatal("foreign Evaluation lease owner was accepted")
	}
	if err := store.CheckRunLeaseTx(ctx, leaseTx, scope, run.ID, currentData.LeaseOwner, "foreign-token", currentData.LeaseUntil, time.Now().UTC()); err == nil {
		_ = leaseTx.Rollback()
		t.Fatal("foreign Evaluation lease token was accepted")
	}
	if err := leaseTx.Rollback(); err != nil {
		t.Fatalf("release Evaluation lease verification transaction: %v", err)
	}
	if _, err := store.RenewRunLease(ctx, scope, run.ID, old.Revision, "token-old", now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale renewal: %v", err)
	}
	// Cancellation wins a CAS; even the current lease must not publish afterward.
	caseData := CaseResultData{RunID: run.ID, Index: 0, InputHash: Checksum([]byte("input")), OutputHash: Checksum([]byte("output")), OutputArtifactID: "artifact-test", ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed", ProducedAt: now, Metrics: []MetricOutcome{{MetricID: "metric-test", Status: "passed", Value: floatPointer(1), Direction: "higher_is_better"}}}
	caseBytes, _ := json.Marshal(caseData)
	caseRow := Resource{ID: caseResultID(run.ID, 0), Kind: KindCaseResult, Scope: scope, Revision: 1, Status: "completed", CreatedBy: "worker", CreatedAt: now, UpdatedAt: now, Data: caseBytes}
	if err := store.CommitRunCase(ctx, scope, run.ID, old.Revision, "token-old", caseRow); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale case commit: %v", err)
	}
	if err := store.CommitRunCase(ctx, scope, run.ID, current.Revision, "token-new", caseRow); err != nil {
		t.Fatalf("owned case commit: %v", err)
	}
	// 取消以 CAS 提交，当前租约持有者也不得覆盖取消状态。
	cancelled := current
	cancelled.Revision++
	cancelled.Status = "cancelled"
	var state RunData
	if err := json.Unmarshal(current.Data, &state); err != nil {
		t.Fatal(err)
	}
	state.ExecutionState = "cancelled"
	state.LeaseToken = ""
	cancelled.Data, _ = json.Marshal(state)
	if err := store.UpdateCAS(ctx, scope, KindRun, run.ID, current.Revision, cancelled); err != nil {
		t.Fatal(err)
	}
	late := current
	caseData.Index = 1
	caseRow.ID = caseResultID(run.ID, 1)
	caseRow.Data, _ = json.Marshal(caseData)
	if err := store.CommitRunCase(ctx, scope, run.ID, current.Revision, "token-new", caseRow); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancelled case commit: %v", err)
	}
	if _, err := store.Get(ctx, scope, KindCaseResult, caseRow.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late case persisted: %v", err)
	}
	late.Revision++
	late.Status = "succeeded"
	state.ExecutionState = "succeeded"
	late.Data, _ = json.Marshal(state)
	if err := store.FinalizeRun(ctx, scope, current.Revision, "token-new", late, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("late finalization: %v", err)
	}
	persisted, err := store.Get(ctx, scope, KindRun, run.ID)
	if err != nil || persisted.Status != "cancelled" || persisted.Revision != cancelled.Revision {
		t.Fatalf("cancellation lost: %+v %v", persisted, err)
	}

	// Exercise the product HTTP boundary against SQL, not only the store CAS.
	// 通过真实 HTTP 取消接口写入 SQL，验证 API、授权、Dispatcher 与 CAS 的组合行为。
	httpRunID := "run-http-cancel"
	httpScope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	httpRunData, _ := json.Marshal(RunData{SuiteID: "suite-http-cancel", IdempotencyKey: "idem-http-cancel", ExecutionState: "dispatch_pending"})
	httpRun := Resource{ID: httpRunID, Kind: KindRun, Scope: httpScope, Status: "queued", Revision: 1, CreatedBy: "alice", CreatedAt: now, UpdatedAt: now, Data: httpRunData}
	if err := store.Create(ctx, httpRun); err != nil {
		t.Fatal(err)
	}
	dispatcher := &fakeDispatcher{}
	module := NewModule(store, "module-secret", allowAuthorizer(func(context.Context, Actor, Action, Scope) error { return nil }), dispatcher)
	response := request(module, http.MethodPost, "/runs/"+httpRunID+"/cancel", `{"expected_revision":1}`, "alice", false)
	if response.Code != http.StatusAccepted {
		t.Fatalf("HTTP cancellation status=%d body=%s", response.Code, response.Body.String())
	}
	httpPersisted, err := store.Get(ctx, httpScope, KindRun, httpRunID)
	if err != nil {
		t.Fatalf("read HTTP-cancelled run: %v", err)
	}
	var httpState RunData
	if err := json.Unmarshal(httpPersisted.Data, &httpState); err != nil || httpPersisted.Status != "cancelling" || httpPersisted.Revision != 2 || httpState.ExecutionState != "cancelling" {
		t.Fatalf("HTTP cancellation was not durably committed: row=%+v state=%+v err=%v", httpPersisted, httpState, err)
	}
	if replay := request(module, http.MethodPost, "/runs/"+httpRunID+"/cancel", `{"expected_revision":1}`, "alice", false); replay.Code != http.StatusConflict {
		t.Fatalf("stale HTTP cancellation should conflict, status=%d body=%s", replay.Code, replay.Body.String())
	}
	dispatcher.mu.Lock()
	cancelCalls := dispatcher.cancelled
	dispatcher.mu.Unlock()
	if cancelCalls != 1 {
		t.Fatalf("stale cancellation replay reached dispatcher: calls=%d", cancelCalls)
	}

	pending, err := store.PendingCancellationRuns(ctx, "", 16)
	if err != nil || len(pending) != 1 || pending[0].ID != httpRunID || pending[0].Status != "cancelling" {
		t.Fatal("durable cancellation recovery queue lost the pending batch", err)
	}
	after, err := store.PendingCancellationRuns(ctx, cancellationCursor(pending[0]), 16)
	if err != nil || len(after) != 0 {
		t.Fatal("cancellation cursor repeated its last batch", err)
	}

	// A restarted Runner instance must recover a persisted RUNNING Run after
	// the prior process exits and its durable lease expires.
	// 新 Runner 实例必须能在旧进程退出且持久化租约到期后恢复 RUNNING Run。
	restartScope := Scope{TenantID: "tenant-runner-restart", DepartmentID: "dept", ApplicationID: "app"}
	restartRunID := fmt.Sprintf("run-restart-%d", time.Now().UnixNano())
	restartRun := seedProductRun(t, store, restartScope, restartRunID, "synthetic_generated", "exact_match", []json.RawMessage{
		json.RawMessage(`{"case_id":"case-1","input":{"question":"restart question"},"expected":{"answer":"approved"}}`),
	})
	firstStarted := make(chan InvocationRequest, 1)
	firstInvoker := &testAgentInvoker{fn: func(ctx context.Context, request InvocationRequest) (InvocationResult, error) {
		firstStarted <- request
		<-ctx.Done()
		return InvocationResult{}, ctx.Err()
	}}
	runnerOptions := RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second}
	firstRunner, err := NewRunner(store, firstInvoker, nil, &testArtifactWriter{}, runnerOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstRunner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := firstRunner.Enqueue(ctx, restartScope, restartRun); err != nil {
		t.Fatal(err)
	}
	var firstRequest InvocationRequest
	select {
	case firstRequest = <-firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first Runner instance did not begin the persisted Run")
	}
	if firstRequest.RunID != restartRunID || firstRequest.IdempotencyKey == "" {
		t.Fatalf("first Runner used an invalid run identity: %+v", firstRequest)
	}
	shutdown, stopRunner := context.WithTimeout(context.Background(), 3*time.Second)
	if err := firstRunner.Close(shutdown); err != nil {
		stopRunner()
		t.Fatalf("stop first Runner instance: %v", err)
	}
	stopRunner()
	interrupted, err := store.Get(ctx, restartScope, KindRun, restartRunID)
	if err != nil || interrupted.Status != "running" {
		t.Fatalf("stopped Runner must leave a recoverable durable Run, row=%+v err=%v", interrupted, err)
	}
	var interruptedData RunData
	if err := json.Unmarshal(interrupted.Data, &interruptedData); err != nil || !interruptedData.LeaseUntil.After(time.Now()) {
		t.Fatalf("stopped Runner did not retain a valid durable lease expiry: data=%+v err=%v", interruptedData, err)
	}
	leaseDelay := time.Until(interruptedData.LeaseUntil) + 25*time.Millisecond
	select {
	case <-time.After(leaseDelay):
	case <-ctx.Done():
		t.Fatalf("wait for old Runner lease expiry: %v", ctx.Err())
	}
	secondStarted := make(chan InvocationRequest, 1)
	secondInvoker := &testAgentInvoker{fn: func(_ context.Context, request InvocationRequest) (InvocationResult, error) {
		secondStarted <- request
		return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	secondRunner, err := NewRunner(store, secondInvoker, nil, &testArtifactWriter{}, runnerOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := secondRunner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer closeCancel()
		if err := secondRunner.Close(closeCtx); err != nil {
			t.Errorf("close recovered Runner: %v", err)
		}
	}()
	recovered := waitForRun(t, store, restartScope, restartRunID, "succeeded")
	var secondRequest InvocationRequest
	select {
	case secondRequest = <-secondStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("restarted Runner did not dispatch the expired Run")
	}
	var recoveredData RunData
	if err := json.Unmarshal(recovered.Data, &recoveredData); err != nil || recoveredData.Attempt < 2 {
		t.Fatalf("restarted Runner did not acquire a new durable attempt: data=%+v err=%v", recoveredData, err)
	}
	if secondInvoker.calls.Load() != 1 || secondRequest.RunID != firstRequest.RunID || secondRequest.IdempotencyKey != firstRequest.IdempotencyKey {
		t.Fatalf("restarted Runner failed stable at-least-once dispatch identity: first=%+v second=%+v calls=%d", firstRequest, secondRequest, secondInvoker.calls.Load())
	}
}

// The SQL store, not an in-memory substitute, must recover an uncertain
// successful finalization without invoking an already persisted Case again.
// 必须在真实 SQL Store 上证明成功终结失败后按租约恢复，而非重调已落库 Case。
func TestSQLSuccessfulFinalizationFailureRecoversWithoutDuplicateInvocation(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("requires the isolated Compose PostgreSQL database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated PostgreSQL DSN")
	}
	admin, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	database := fmt.Sprintf("eval_finalize_%d", time.Now().UnixNano())
	if _, err := admin.Exec(sqlutil.Bind("CREATE DATABASE " + database)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(sqlutil.Bind("DROP DATABASE " + database)); err != nil {
			t.Error(err)
		}
	}()
	config.Database = database
	db := stdlib.OpenDB(*config)
	err = db.PingContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: "tenant-finalize", DepartmentID: "dept", ApplicationID: "app"}
	run := seedProductRun(t, store, scope, "run-finalize", "synthetic_generated", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	fault := &faultExecutionStore{ExecutionStore: store}
	fault.claimFailures.Store(2)
	fault.finalizeFailures.Store(1)
	invoker := &testAgentInvoker{fn: func(context.Context, InvocationRequest) (InvocationResult, error) {
		return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	opts := RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second}
	first, err := NewRunner(fault, invoker, nil, &testArtifactWriter{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for first.Stats().FinalizeFailures < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.Stats().ClaimFailures != 2 || first.Stats().FinalizeFailures != 1 {
		t.Fatalf("SQL-backed worker fault signals were not observed: %+v", first.Stats())
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Get(ctx, scope, KindRun, run.ID)
	if err != nil || persisted.Status != "running" || invoker.calls.Load() != 1 {
		t.Fatalf("SQL failure altered durable state or invocation count: status=%s calls=%d err=%v", persisted.Status, invoker.calls.Load(), err)
	}
	// Expire only this isolated fixture's lease; production waits for TTL.
	// 仅过期隔离测试库中的租约；生产按实际 TTL 等待。
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_evaluation_product_run_lease SET lease_expires_at=clock_timestamp() - INTERVAL '1 second' WHERE tenant_id=? AND department_id=? AND application_id=? AND run_id=?`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, run.ID); err != nil {
		t.Fatal(err)
	}
	second, err := NewRunner(fault, invoker, nil, &testArtifactWriter{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := second.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		persisted, err = store.Get(ctx, scope, KindRun, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Status == "succeeded" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if persisted.Status != "succeeded" || invoker.calls.Load() != 1 {
		t.Fatalf("SQL recovery status=%s calls=%d", persisted.Status, invoker.calls.Load())
	}
}

// TestSeedPlatformProcessRestartRun leaves one expired durable Run in the
// disposable Compose database. The host E2E stops platform-app before running
// this fixture and starts it again afterward, exercising the real module
// lifecycle recovery path across an operating-system process restart.
// 为真实 Compose E2E 留下一条过期租约 Run；平台容器停止期间写入，重启后验证模块启动恢复。
func TestSeedPlatformProcessRestartRun(t *testing.T) {
	if os.Getenv("LEXAGENT_E2E_PLATFORM_RESTART_SEED") != "1" {
		t.Skip("only run by the isolated modular Compose process-restart E2E")
	}
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	suiteID := os.Getenv("LEXAGENT_E2E_EVALUATION_SUITE_ID")
	if dsn == "" || !validID(suiteID) {
		t.Fatal("isolated PostgreSQL DSN and valid Evaluation suite ID are required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: "tenant-demo", DepartmentID: "dept-demo", ApplicationID: "app-demo"}
	suiteRow, err := store.Get(ctx, scope, KindSuite, suiteID)
	if err != nil {
		t.Fatalf("load published suite for restart fixture: %v", err)
	}
	var suite SuiteData
	if err := json.Unmarshal(suiteRow.Data, &suite); err != nil || !validID(suite.AgentID) || !validID(suite.AgentVersionID) {
		t.Fatalf("published suite has invalid Agent binding: %+v err=%v", suite, err)
	}
	runID, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	runID = "restart-" + runID
	now := time.Now().UTC()
	runData, err := json.Marshal(RunData{
		SuiteID: suiteID, AgentID: suite.AgentID, AgentVersionID: suite.AgentVersionID,
		IdempotencyKey: "platform-restart." + runID, ExecutionState: "dispatch_pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	run := Resource{ID: runID, Kind: KindRun, Scope: scope, Status: "queued", Revision: 1, CreatedBy: "fixture.operator", CreatedAt: now, UpdatedAt: now, Data: runData}
	if err := store.Create(ctx, run); err != nil {
		t.Fatalf("create restart recovery Run: %v", err)
	}
	// Use the real claim transaction to persist a RUNNING state whose lease has
	// already elapsed before the platform process is brought back.
	// 使用真实 Claim 事务生成进程重启前状态，并令持久化租约在新进程启动前过期。
	claimTime := now.Add(-2 * time.Minute)
	claimed, ok, err := store.ClaimNextRun(ctx, "process-before-restart", "lease-before-restart", claimTime, time.Minute)
	if err != nil || !ok || claimed.ID != runID {
		t.Fatalf("seed expired pre-restart claim: claimed=%v run=%s want=%s err=%v", ok, claimed.ID, runID, err)
	}
	fmt.Printf("EVAL_RECOVERY_RUN_ID=%s\n", runID)
}
