package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Recovery is a stop barrier, not permission to re-enter a live graph.
// 恢复需要停止屏障，不能因为租约过期就再次进入正在执行的图。
func TestExpiredOwnerRecoveryKeepsCommandAndReservationUntilStop(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("recover-generation")
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "recovery", Fingerprint: "fixture", RequestJSON: gatewayRequest(t, scope, "invoke"), AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "old-owner", time.Now().UTC(), 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(claimed.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	var originalCommand contract.ExecuteRequest
	if err := json.Unmarshal(running.RequestJSON, &originalCommand); err != nil {
		t.Fatal(err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(originalCommand)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := originalCommand.Input["policy_snapshot"].(map[string]any)
	policyHash, _ := snapshot["content_hash"].(string)
	if err := store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: "invoke", BodyHash: bodyHash, PolicyHash: policyHash}, running.LeaseToken); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(running.LeaseUntil) + time.Millisecond)
	if _, err := store.AcquireLease(running.ID, "new-owner", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("expired token silently stolen")
	}
	gateway := &uncertainGateway{}
	d := NewDispatcherWithGateway(store, "", gateway, 1)
	d.SetSecurity(machineRunContextSignerFunc(func(ctx context.Context, _ sharedkernel.Scope, request contract.ExecuteRequest) (string, error) {
		binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
		if !ok || binding.Revision != running.Revision || request.Operation != "cancel" {
			t.Fatal("recovery did not stop original generation")
		}
		return "fresh-stop-token", nil
	}), nil)
	if err := d.dispatch(context.Background(), running); err == nil {
		t.Fatal("failed stop acknowledged")
	}
	pending, err := store.Get(running.ID)
	if err != nil || pending.Status != platformruntime.StatusRecovering || pending.LeaseToken != running.LeaseToken || gateway.invocations != 0 {
		t.Fatal("old owner was reexecuted or finalized")
	}
	nextScope := scope.domain()
	nextScope.RunID = "recovery-next"
	_, err = store.Create(platformruntime.CreateRequest{ID: nextScope.RunID, Scope: nextScope, AgentVersionID: "v1", IdempotencyKey: "next", Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(nextScope.RunID, "next-owner", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("recovery released FIFO")
	}
	gateway.confirm = true
	settled := false
	module := NewModuleWithDispatcher("", store, d)
	module.SetStopQuiescence(func(_ context.Context, owner sharedkernel.Scope) error {
		if owner != running.Scope {
			t.Fatal("recovery ledger check lost owner scope")
		}
		if !settled {
			return errors.New("unsettled provider")
		}
		return nil
	})
	d.reconcileCancellations(context.Background())
	unsettled, err := store.Get(running.ID)
	if err != nil || unsettled.Status != platformruntime.StatusRecovering || unsettled.LeaseToken != running.LeaseToken || gateway.invocations != 0 {
		t.Fatal("recovery passed remote stop but bypassed unsettled billing")
	}
	settled = true
	// The failed attempt scheduled a backoff hint; expire it rather than sleep.
	d.cancellationRetries = nil
	d.reconcileCancellations(context.Background())
	recovered, err := store.Get(running.ID)
	if err != nil || recovered.Status != platformruntime.StatusRunning || recovered.LeaseToken != "" || string(recovered.RequestJSON) != string(running.RequestJSON) || gateway.invocations != 0 {
		t.Fatal("recovery lost original command or became cancellation")
	}
	if _, err := store.GetOutcome(running.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatal("recovery fabricated a cancelled outcome")
	}
	pendingRuns, err := store.ListPending(16)
	if err != nil || len(pendingRuns) != 1 || pendingRuns[0].ID != running.ID {
		t.Fatal("recovered command cannot be found after restart")
	}
	if _, err := store.AcquireLease(running.ID, "new-owner", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("stop ACK did not allow original Run to continue")
	}
	if _, err := store.AcquireLease(nextScope.RunID, "next-owner", time.Now().UTC(), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("recovery incorrectly released FIFO to next Run")
	}
}
