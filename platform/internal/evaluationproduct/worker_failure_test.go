package evaluationproduct

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type faultExecutionStore struct {
	ExecutionStore
	claimFailures    atomic.Int32
	finalizeFailures atomic.Int32
}

func (s *faultExecutionStore) ClaimNextRun(ctx context.Context, owner, token string, now time.Time, ttl time.Duration) (Resource, bool, error) {
	if s.claimFailures.Add(-1) >= 0 {
		return Resource{}, false, errors.New("transient claim database failure")
	}
	return s.ExecutionStore.ClaimNextRun(ctx, owner, token, now, ttl)
}

func (s *faultExecutionStore) FinalizeRun(ctx context.Context, scope Scope, revision uint64, token string, row Resource, evidence *Resource) error {
	if s.finalizeFailures.Add(-1) >= 0 {
		return errors.New("transient finalize database failure")
	}
	return s.ExecutionStore.FinalizeRun(ctx, scope, revision, token, row, evidence)
}

// A transient storage failure is observable and retries the fenced write only.
// 暂态存储故障可观测，失败终结重试不再次调用 Agent。
func TestWorkerClaimAndFailedFinalizationRecoverWithoutRepeatedInvocation(t *testing.T) {
	base := newMemoryStore()
	scope := Scope{TenantID: "tenant-fault", DepartmentID: "department-fault", ApplicationID: "app-fault"}
	// Unit-only frozen fixture; no real business-quality claim is made.
	// 仅为单测冻结夹具，不代表真实业务金标或准确率证据。
	run := seedProductRun(t, base, scope, "run-fault", "manual_gold", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	fault := &faultExecutionStore{ExecutionStore: base}
	fault.claimFailures.Store(2)
	fault.finalizeFailures.Store(2)
	invoker := &testAgentInvoker{fn: func(context.Context, InvocationRequest) (InvocationResult, error) {
		return InvocationResult{}, errors.New("upstream failed")
	}}
	runner, err := NewRunner(fault, invoker, nil, &testArtifactWriter{}, RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runner.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runner.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	if err := runner.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	waitForRun(t, base, scope, run.ID, "failed")
	stats := runner.Stats()
	if stats.ClaimFailures != 2 || stats.FinalizeFailures != 2 {
		t.Fatalf("error counters lost: %+v", stats)
	}
	if invoker.calls.Load() != 1 {
		t.Fatalf("Agent reran to repair persistence: %d", invoker.calls.Load())
	}
}

func TestWorkerBackoffStopsImmediatelyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if waitWorkerRetry(ctx, time.Minute) || time.Since(start) > time.Second {
		t.Fatal("cancelled retry waited or reported success")
	}
}

func TestWorkerReadinessTracksSustainedClaimFailuresAndRecovery(t *testing.T) {
	base := newMemoryStore()
	fault := &faultExecutionStore{ExecutionStore: base}
	fault.claimFailures.Store(100)
	runner, err := NewRunner(fault, &testAgentInvoker{}, nil, &testArtifactWriter{}, RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	module := NewModule(base, "test-internal-token", nil, runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := module.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := module.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for runner.Stats().ClaimFailures < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.Stats().ClaimFailures < 3 || module.Ready() == nil {
		t.Fatal("sustained queue outage was reported ready")
	}
	if stats := runner.Stats(); stats.Ready || stats.Capacity != 1 || stats.ClaimFailures < 3 {
		t.Fatalf("worker outage metrics do not reflect failed claims: %+v", stats)
	}
	// Restore the repository and wait for an actual successful empty claim.
	// 恢复数据库后须等真实领取成功，不能仅重置测试计数就宣称健康。
	fault.claimFailures.Store(0)
	for module.Ready() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := module.Ready(); err != nil {
		t.Fatalf("worker did not recover readiness: %v", err)
	}
	if stats := runner.Stats(); !stats.Ready {
		t.Fatalf("worker recovery metrics did not clear: %+v", stats)
	}
}

// A failed terminal write must be recoverable after ownership changes. The
// invoker fixture models the production child Run's durable idempotency key;
// only the downstream effect, not the at-least-once transport call, is unique.
// 终结落库失败跨租约恢复时，传输可重试，但子 Run 的副作用只能提交一次。
func TestWorkerFinalizeOutageRecoversAfterLeaseWithoutDuplicateEffect(t *testing.T) {
	base := newMemoryStore()
	scope := Scope{TenantID: "tenant-lease-fault", DepartmentID: "dept", ApplicationID: "app"}
	run := seedProductRun(t, base, scope, "run-lease-fault", "synthetic_generated", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	fault := &faultExecutionStore{ExecutionStore: base}
	fault.finalizeFailures.Store(3)
	var transportCalls atomic.Int32
	var committedEffects atomic.Int32
	var firstKey string
	invoker := &testAgentInvoker{fn: func(_ context.Context, req InvocationRequest) (InvocationResult, error) {
		transportCalls.Add(1)
		if req.RunID != run.ID || req.IdempotencyKey == "" {
			return InvocationResult{}, errors.New("invalid frozen child identity")
		}
		if firstKey == "" {
			firstKey = req.IdempotencyKey
		} else if firstKey != req.IdempotencyKey {
			return InvocationResult{}, errors.New("child idempotency key changed across recovery")
		}
		if committedEffects.Add(1) == 1 {
			// Simulate a provider response lost after its effect was committed.
			// 模拟供应商已提交但响应丢失，恢复须回放而非再次扣费。
			return InvocationResult{}, errors.New("response lost after commit")
		}
		committedEffects.Add(-1) // A durable child Run replays the same receipt.
		return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	opts := RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second}
	first, err := NewRunner(fault, invoker, nil, &testArtifactWriter{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for first.Stats().FinalizeFailures < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.Stats().FinalizeFailures != 3 || transportCalls.Load() != 1 {
		t.Fatalf("first attempt: stats=%+v transport=%d", first.Stats(), transportCalls.Load())
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Advance the persisted lease clock without making the test sleep 10 s.
	// 仅在测试存储中推进持久化租约，生产仍按真实租约时钟工作。
	base.mu.Lock()
	key := resourceKey(scope, KindRun, run.ID)
	stale := base.rows[key]
	var data RunData
	if err := json.Unmarshal(stale.Data, &data); err != nil {
		base.mu.Unlock()
		t.Fatal(err)
	}
	data.LeaseUntil = time.Now().Add(-time.Second)
	stale.Data, _ = json.Marshal(data)
	base.rows[key] = stale
	base.mu.Unlock()
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
	recovered := waitForRun(t, base, scope, run.ID, "succeeded")
	var recoveredData RunData
	if err := json.Unmarshal(recovered.Data, &recoveredData); err != nil || recoveredData.Attempt != 2 {
		t.Fatalf("not reclaimed exactly once: %+v %v", recoveredData, err)
	}
	if transportCalls.Load() != 2 || committedEffects.Load() != 1 {
		t.Fatalf("transport=%d effect=%d", transportCalls.Load(), committedEffects.Load())
	}
}

// A success commit may fail after every case has been durably saved. Recovery
// must replay the case receipt, not invoke the Agent again or turn the Run
// into a false failed terminal state.
// 所有 Case 已持久化后成功终结写入可能失败；恢复只能重放 Case 回执，
// 不得重调 Agent，也不得把未知提交结果误写成失败终态。
func TestSuccessfulFinalizationFailureReclaimsWithoutDuplicateAgentCall(t *testing.T) {
	base := newMemoryStore()
	scope := Scope{TenantID: "tenant-success-finalize", DepartmentID: "dept", ApplicationID: "app"}
	run := seedProductRun(t, base, scope, "run-success-finalize", "synthetic_generated", "exact_match", []json.RawMessage{json.RawMessage(`{"case_id":"case-1","input":{"question":"q"},"expected":{"answer":"approved"}}`)})
	fault := &faultExecutionStore{ExecutionStore: base}
	fault.finalizeFailures.Store(1)
	invoker := &testAgentInvoker{fn: func(context.Context, InvocationRequest) (InvocationResult, error) {
		return InvocationResult{Output: json.RawMessage(`{"answer":"approved"}`), ProviderMode: "real", CitationGrounding: "passed", DomainGrounding: "passed"}, nil
	}}
	opts := RunnerOptions{PollInterval: 10 * time.Millisecond, LeaseDuration: 10 * time.Second, CaseTimeout: time.Second}
	first, err := NewRunner(fault, invoker, nil, &testArtifactWriter{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := first.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.Enqueue(ctx, scope, run); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for first.Stats().FinalizeFailures < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.Stats().FinalizeFailures != 1 {
		t.Fatal("success finalization failure was not observable")
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, err := base.Get(ctx, scope, KindRun, run.ID)
	if err != nil || stored.Status != "running" {
		t.Fatalf("failed commit silently changed durable status: %+v %v", stored, err)
	}
	if invoker.calls.Load() != 1 {
		t.Fatalf("Agent calls before recovery=%d", invoker.calls.Load())
	}
	// Advance only the fixture's persisted lease; production waits for TTL.
	// 仅推进测试存储中的持久化租约；生产依照真实 TTL 接管。
	base.mu.Lock()
	key := resourceKey(scope, KindRun, run.ID)
	stale := base.rows[key]
	var data RunData
	if err := json.Unmarshal(stale.Data, &data); err != nil {
		base.mu.Unlock()
		t.Fatal(err)
	}
	data.LeaseUntil = time.Now().Add(-time.Second)
	stale.Data, _ = json.Marshal(data)
	base.rows[key] = stale
	base.mu.Unlock()
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
	recovered := waitForRun(t, base, scope, run.ID, "succeeded")
	if invoker.calls.Load() != 1 {
		t.Fatalf("recovery repeated Agent effect: calls=%d status=%s", invoker.calls.Load(), recovered.Status)
	}
}
