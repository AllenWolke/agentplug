package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func TestCancellationIntentBlocksCapabilitiesAndRetainsSession(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("cancel-intent").domain()
	create := func(id string) platformruntime.Run {
		scope.RunID = id
		created, err := store.Create(platformruntime.CreateRequest{ID: id, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: id, Fingerprint: id})
		if err != nil {
			t.Fatal(err)
		}
		return created.Run
	}
	first, next := create("cancel-first"), create("cancel-next")
	claimed, err := store.AcquireLease(first.ID, "worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(first.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginCancellation(first.ID, running.Revision+1); !errors.Is(err, platformruntime.ErrRevisionConflict) {
		t.Fatalf("bad CAS accepted: %v", err)
	}
	pending, err := store.BeginCancellation(first.ID, running.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != platformruntime.StatusCancelling || pending.LeaseToken != running.LeaseToken || !pending.LeaseUntil.Equal(running.LeaseUntil) {
		t.Fatal("intent released lease")
	}
	if err := NewModuleWithSharedRepository("", store).ValidateLiveCommand(context.Background(), pending.Scope, "invoke", "body", "policy"); err == nil {
		t.Fatal("cancel requested still authorizes capabilities")
	}
	if _, err := store.AcquireLease(next.ID, "another-worker", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("session released before stop ACK: %v", err)
	}
	if _, err := store.AcquireLease(next.ID, "another-worker", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatalf("expired lease bypassed pending cancellation: %v", err)
	}
	if _, err := store.FinalizeLeased(first.ID, platformruntime.StatusSucceeded, running.Revision, running.LeaseToken, nil, nil); err == nil {
		t.Fatal("late success won against cancel intent")
	}
	// Only the stop-ACK owner may call the final transition in the application.
	// 应用仅在获得停止 ACK 后调用最终迁移；仓储在此才释放会话。
	if _, err := store.Cancel(first.ID, pending.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(next.ID, "another-worker", time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("session not released after ACK: %v", err)
	}
}
