package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type partialProjectionRecorder struct{ healthyResults, healthyCreations int }

func (r *partialProjectionRecorder) RecordRunResult(_ context.Context, _ sharedkernel.Scope, id string, _ map[string]any) error {
	if id != "z-healthy" {
		return errors.New("per-record failure")
	}
	r.healthyResults++
	return nil
}
func (r *partialProjectionRecorder) RecordRun(_ context.Context, s sharedkernel.Scope, _ []byte) error {
	if s.RunID != "z-healthy" {
		return errors.New("per-record failure")
	}
	r.healthyCreations++
	return nil
}

// Poison records remain durable but cannot monopolize the first repair page.
// 失败记录继续持久化，但不得永远占据补偿首批，饿死其他租户的正常记录。
func TestProjectionFairnessAcrossPoisonPageAndRestart(t *testing.T) {
	store := platformruntime.NewStore()
	for i := 0; i < 65; i++ {
		id := fmt.Sprintf("a-%02d", i)
		if i == 64 {
			id = "z-healthy"
		}
		scope := testScope(id).domain()
		scope.SessionID = id
		created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: "v1", IdempotencyKey: id, Fingerprint: id})
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := store.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		running, err := store.TransitionLeased(id, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, "owner")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.FinalizeLeased(id, platformruntime.StatusSucceeded, running.Revision, "owner", map[string]any{"answer": "value"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	recorder := &partialProjectionRecorder{}
	d := NewDispatcher(store, "", 1)
	d.SetResultRecorder(recorder)
	d.conversation = recorder
	for i := 0; i < 3; i++ {
		d.reconcileOutcomes(context.Background())
		d.reconcileCreations(context.Background())
	}
	if recorder.healthyResults != 1 || recorder.healthyCreations != 1 {
		t.Fatalf("healthy row starved: %+v", recorder)
	}
	pending, err := store.PendingOutcomes(256)
	if err != nil || len(pending) != 64 {
		t.Fatalf("poison intents lost: %d %v", len(pending), err)
	}
	// A new instance starts scanning from the beginning, with no lost facts.
	// 新实例游标归零不丢持久化事实，也不再次投影已确认结果。
	restarted := NewDispatcher(store, "", 1)
	restarted.SetResultRecorder(recorder)
	for i := 0; i < 3; i++ {
		restarted.reconcileOutcomes(context.Background())
	}
	if recorder.healthyResults != 1 {
		t.Fatal("acknowledged outcome replayed")
	}
}
