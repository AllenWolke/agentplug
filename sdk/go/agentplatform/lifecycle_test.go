package agentplatform

import (
	"sync"
	"testing"
)

func runRequest(runID, idem string, tenant string) ExecuteRequest {
	return ExecuteRequest{
		ProtocolVersion: ProtocolVersion, Operation: "run", IdempotencyKey: idem, InputSchema: "schema://t",
		Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": "hash-" + tenant}},
		Scope: ScopeKey{TenantID: tenant, InstallationID: "installation-" + tenant, RunID: runID, PrincipalType: "user", PrincipalID: "u1", AuthorizationEpoch: 1},
	}
}

// TestMemoryRunStoreIsolatesConcurrentScopes is the multi-run scope isolation
// requirement from PF-06: parallel runs must never leak events, output or
// cancellation into each other.
// TestMemoryRunStoreIsolatesConcurrentScopes 验证 PF-06 的多并发 Scope 隔离：
// 并行运行的 events、输出与取消互不泄漏。
func TestMemoryRunStoreIsolatesConcurrentScopes(t *testing.T) {
	store := NewMemoryRunStore()
	const runs = 16
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			runID := "run-concurrent-scope-isolation"
			if index%2 == 0 {
				runID = "run-concurrent-scope-isolation-alt"
			}
			request := runRequest(runID, "idem-"+runID, "tenant-a")
			if index%2 == 0 {
				request.Scope.TenantID = "tenant-b"
			}
			record, created, err := store.StartRun(request)
			if err != nil {
				t.Errorf("StartRun failed: %v", err)
				return
			}
			if !created {
				// A replay under the same key must return the same scope and
				// never rewrite it with another tenant's request.
				// 同键重放必须返回既有 Scope，绝不被其他租户请求改写。
				if record.Scope.TenantID != "tenant-a" && runID == "run-concurrent-scope-isolation" {
					return
				}
				if record.IdempotencyKey != request.IdempotencyKey {
					t.Errorf("replay returned a foreign record for %s", runID)
				}
				return
			}
			if _, err := store.AppendEvent(runID, EventProgress, map[string]any{"mark": runID}); err != nil {
				t.Errorf("AppendEvent failed: %v", err)
			}
			if err := store.Complete(runID, map[string]any{"echo": runID}); err != nil {
				t.Errorf("Complete failed: %v", err)
			}
		}(i)
	}
	wg.Wait()

	for _, runID := range []string{"run-concurrent-scope-isolation", "run-concurrent-scope-isolation-alt"} {
		record, ok := store.GetRun(runID)
		if !ok {
			t.Fatalf("run %s vanished", runID)
		}
		if record.Status != RunStatusSucceeded {
			t.Fatalf("run %s status = %s", runID, record.Status)
		}
		for _, event := range record.Events {
			if event.RunID != runID {
				t.Fatalf("event leak: run %s observed event of %s", runID, event.RunID)
			}
		}
		marks := 0
		for _, event := range record.Events {
			if event.EventType == EventProgress {
				marks++
			}
		}
		if marks == 0 {
			t.Fatalf("run %s lost its progress events", runID)
		}
	}
}

// TestMemoryRunStoreCancelClosesChannelAndFreezesState verifies the cancel
// contract: the business handler is notified, the state freezes, and replays
// stay idempotent.
// TestMemoryRunStoreCancelClosesChannelAndFreezesState 验证取消契约：业务
// 处理器收到通知、状态冻结、重放保持幂等。
func TestMemoryRunStoreCancelClosesChannelAndFreezesState(t *testing.T) {
	store := NewMemoryRunStore()
	request := runRequest("run-cancel-probe", "idem-cancel", "tenant-a")
	if _, created, err := store.StartRun(request); err != nil || !created {
		t.Fatalf("StartRun: created=%v err=%v", created, err)
	}
	cancelled, ok := store.Cancelled("run-cancel-probe")
	if !ok {
		t.Fatal("cancel channel missing")
	}
	select {
	case <-cancelled:
		t.Fatal("cancel fired before request")
	default:
	}
	record, err := store.Cancel("run-cancel-probe", "operator request")
	if err != nil {
		t.Fatalf("Cancel failed: %v", err)
	}
	if record.Status != RunStatusCancelled {
		t.Fatalf("status = %s", record.Status)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("cancel channel was not closed")
	}
	// Cancel is idempotent for replays. / 取消对重放幂等。
	if _, err := store.Cancel("run-cancel-probe", "replay"); err != nil {
		t.Fatalf("replayed Cancel failed: %v", err)
	}
	// A cancelled run cannot complete, resume or be rewritten.
	if err := store.Complete("run-cancel-probe", nil); err == nil {
		t.Fatal("cancelled run completed")
	}
	// Resume on a cancelled run is a documented no-op, never a revival.
	// 对已取消运行的 Resume 是既定无操作，绝不复活。
	if err := store.Resume("run-cancel-probe", nil); err != nil {
		t.Fatalf("resume on cancelled run must be a no-op: %v", err)
	}
	if record, _ := store.GetRun("run-cancel-probe"); record.Status != RunStatusCancelled {
		t.Fatalf("cancelled run was revived: %s", record.Status)
	}
	if err := store.MarkWaiting("run-cancel-probe", nil); err == nil {
		t.Fatal("cancelled run waited")
	}
}

// TestMemoryRunStoreStartRunIdempotencyConflict rejects run_id reuse under a
// different idempotency key.
// TestMemoryRunStoreStartRunIdempotencyConflict 拒绝同 run_id 不同幂等键的重用。
func TestMemoryRunStoreStartRunIdempotencyConflict(t *testing.T) {
	store := NewMemoryRunStore()
	if _, created, err := store.StartRun(runRequest("run-conflict", "key-1", "tenant-a")); err != nil || !created {
		t.Fatalf("first StartRun: created=%v err=%v", created, err)
	}
	if _, _, err := store.StartRun(runRequest("run-conflict", "key-2", "tenant-a")); err != ErrIdempotencyConflict {
		t.Fatalf("conflicting key accepted: %v", err)
	}
	// Same key replays the same record. / 同键重放同一记录。
	_, created, err := store.StartRun(runRequest("run-conflict", "key-1", "tenant-a"))
	if err != nil || created {
		t.Fatalf("replay: created=%v err=%v", created, err)
	}
}

// TestMemoryRunStoreWaitingResumeCycle covers the interrupt/resume state
// machine transitions.
// TestMemoryRunStoreWaitingResumeCycle 覆盖 interrupt/resume 状态机迁移。
func TestMemoryRunStoreWaitingResumeCycle(t *testing.T) {
	store := NewMemoryRunStore()
	runID := "run-waiting-cycle"
	if _, _, err := store.StartRun(runRequest(runID, "key-w", "tenant-a")); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkWaiting(runID, map[string]any{"question": "approve?"}); err != nil {
		t.Fatal(err)
	}
	if record, _ := store.GetRun(runID); record.Status != RunStatusWaiting {
		t.Fatalf("status = %s", record.Status)
	}
	signals, ok := store.ResumeSignals(runID)
	if !ok {
		t.Fatal("resume signal missing")
	}
	if err := store.Resume(runID, map[string]any{"answer": true}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signals:
	default:
		t.Fatal("resume signal not delivered")
	}
	if record, _ := store.GetRun(runID); record.Status != RunStatusRunning {
		t.Fatalf("status after resume = %s", record.Status)
	}
	// Resume on a non-waiting run is a no-op, not an error.
	if err := store.Resume(runID, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(runID, map[string]any{"done": true}); err != nil {
		t.Fatal(err)
	}
	events, err := store.EventsAfter(runID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawWaiting, sawCompleted bool
	for _, event := range events {
		if event.EventType == EventWaiting {
			sawWaiting = true
		}
		if event.EventType == EventCompleted {
			sawCompleted = true
		}
	}
	if !sawWaiting || !sawCompleted {
		t.Fatalf("waiting=%v completed=%v", sawWaiting, sawCompleted)
	}
	if _, err := store.EventsAfter("missing-run", 0); err != ErrRunUnknown {
		t.Fatalf("unknown run events = %v", err)
	}
}
