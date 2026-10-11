package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type failingOutcomeRecorder struct {
	fail   bool
	calls  int
	answer string
}

func (r *failingOutcomeRecorder) RecordRunResult(_ context.Context, _ sharedkernel.Scope, _ string, output map[string]any) error {
	r.calls++
	if r.fail {
		return errors.New("simulated projection outage")
	}
	r.answer, _ = output["answer"].(string)
	return nil
}

func TestProjectionOutageRecoversPersistedResultWithoutAgentInvocation(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("projection-outage").domain()
	scope.SessionID = "isolated-session"
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: "v1", IdempotencyKey: "outcome-recovery", Fingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	recorder := &failingOutcomeRecorder{fail: true}
	d := NewDispatcher(store, "", 1)
	d.SetResultRecorder(recorder)
	if err := d.finish(running, platformruntime.StatusSucceeded, map[string]any{"answer": "saved response"}, nil); err != nil {
		t.Fatal(err)
	}
	final, _ := store.Get(running.ID)
	pending, _ := store.PendingOutcomes(10)
	if final.Status != platformruntime.StatusSucceeded || len(pending) != 1 {
		t.Fatal("projection failure lost durable result or terminal state")
	}
	// A fresh dispatcher has no Agent transport and must still repair history.
	// 新调度器不配置 Agent Transport，仍能补历史，证明不会重跑模型或工具。
	restarted := NewDispatcher(store, "", 1)
	recorder.fail = false
	restarted.SetResultRecorder(recorder)
	restarted.reconcile(context.Background())
	pending, _ = store.PendingOutcomes(10)
	if len(pending) != 0 || recorder.answer != "saved response" || recorder.calls != 2 || len(restarted.queue) != 0 {
		t.Fatalf("repair re-executed or lost response: %+v calls=%d", pending, recorder.calls)
	}
}
