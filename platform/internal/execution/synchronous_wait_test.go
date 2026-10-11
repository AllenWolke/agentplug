package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// This gateway models durable review interruption; only the explicit fixture
// review below resumes it. No timer/reader automatically approves a review.
type synchronousReviewGateway struct {
	invokes       atomic.Int32
	resumes       atomic.Int32
	beforeSuccess func()
}

func (g *synchronousReviewGateway) Invoke(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.invokes.Add(1)
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "waiting", Output: map[string]any{"stage": "waiting_review"}}, nil
}

func (g *synchronousReviewGateway) Resume(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.resumes.Add(1)
	if g.beforeSuccess != nil {
		g.beforeSuccess()
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded", Output: map[string]any{"answer": "reviewed result"}}, nil
}

type synchronousReviewFixture struct {
	module  *Module
	store   *platformruntime.Store
	gateway *synchronousReviewGateway
	scope   sharedkernel.Scope
	request contract.ExecuteRequest
	revoked atomic.Bool
}

func newSynchronousReviewFixture(t *testing.T) *synchronousReviewFixture {
	t.Helper()
	f := &synchronousReviewFixture{store: platformruntime.NewStore(), gateway: &synchronousReviewGateway{}}
	f.scope = testScope("reviewed-evaluation-child").domain()
	f.scope.ParentRunID = "evaluation-product-run"
	if err := json.Unmarshal(gatewayRequest(t, testScope(f.scope.RunID), "invoke"), &f.request); err != nil {
		t.Fatal(err)
	}
	f.request.Scope.ParentRunID = f.scope.ParentRunID
	dispatcher := NewDispatcherWithGateway(f.store, "", f.gateway, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-governed-context-token-000000000000000000000000", nil
	}), func(context.Context, sharedkernel.Scope) error { return nil })
	f.module = NewModuleWithDispatcherAndSharedRepository("", f.store, dispatcher)
	f.module.SetSynchronousRunAuthorizer(func(context.Context, sharedkernel.Scope, string, contract.ExecuteRequest) error {
		if f.revoked.Load() {
			return contract.ErrPermissionDenied
		}
		return nil
	})
	return f
}

func (f *synchronousReviewFixture) waitForStatus(t *testing.T, wanted platformruntime.Status) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if run, err := f.store.Get(f.scope.RunID); err == nil && run.Status == wanted {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Run did not reach %s", wanted)
}

type synchronousCallResult struct {
	response contract.ExecuteResponse
	err      error
}

func (f *synchronousReviewFixture) invoke(ctx context.Context) <-chan synchronousCallResult {
	result := make(chan synchronousCallResult, 1)
	go func() {
		response, err := f.module.InvokeSynchronous(ctx, f.scope, "http://agent.example", f.request)
		result <- synchronousCallResult{response, err}
	}()
	return result
}

func (f *synchronousReviewFixture) approve(t *testing.T) {
	t.Helper()
	run, err := f.store.PrepareResume(f.scope.RunID, []byte(`{"decision":"approve"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.module.dispatcher.dispatch(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}

func TestSynchronousReviewWaitsForExistingRunWithoutAutoApproval(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	select {
	case got := <-result:
		t.Fatalf("waiting was returned as a case result: %+v", got)
	case <-time.After(80 * time.Millisecond):
	}
	if f.gateway.resumes.Load() != 0 {
		t.Fatal("reader automatically approved a review")
	}
	f.approve(t)
	got := <-result
	if got.err != nil || got.response.Status != "succeeded" || got.response.Output["answer"] != "reviewed result" {
		t.Fatalf("terminal result: %+v", got)
	}
	if f.gateway.invokes.Load() != 1 || f.gateway.resumes.Load() != 1 {
		t.Fatal("review caused a duplicate invocation")
	}
}

func TestSynchronousReviewReconnectReusesWaitingChild(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	first := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	cancel()
	if got := <-first; !errors.Is(got.err, context.Canceled) {
		t.Fatalf("disconnect: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusWaiting {
		t.Fatalf("worker exit destroyed waiting Run: %s", run.Status)
	}
	restarted := NewDispatcherWithGateway(f.store, "", f.gateway, 1)
	restarted.SetSecurity(f.module.dispatcher.signer, f.module.dispatcher.authorize)
	replacement := NewModuleWithDispatcherAndSharedRepository("", f.store, restarted)
	replacement.SetSynchronousRunAuthorizer(f.module.synchronousRunAuthorizer)
	f.module = replacement
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer secondCancel()
	second := f.invoke(secondCtx)
	f.approve(t)
	if got := <-second; got.err != nil || got.response.Status != "succeeded" {
		t.Fatalf("reconnect: %+v", got)
	}
	if f.gateway.invokes.Load() != 1 || f.gateway.resumes.Load() != 1 {
		t.Fatal("reconnect replayed business work")
	}
}

func TestSynchronousReviewRevocationRequestsStopWithoutResult(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	f.revoked.Store(true)
	got := <-result
	if !errors.Is(got.err, contract.ErrPermissionDenied) || got.response.Output != nil {
		t.Fatalf("revoked read returned evidence: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusCancelling {
		t.Fatalf("missing durable stop intent: %s", run.Status)
	}
	if f.gateway.invokes.Load() != 1 || f.gateway.resumes.Load() != 0 {
		t.Fatal("revocation repeated or approved business work")
	}
}

func TestSynchronousResultReadRechecksRevocationAfterReview(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	f.gateway.beforeSuccess = func() { f.revoked.Store(true) }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	f.approve(t)
	if got := <-result; !errors.Is(got.err, contract.ErrPermissionDenied) || got.response.Output != nil {
		t.Fatalf("terminal read bypassed revocation: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusSucceeded {
		t.Fatal("revocation rewrote existing terminal history")
	}
}

func TestSynchronousReviewDeadlineKeepsUnconfirmedStopPending(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	got := <-f.invoke(ctx)
	if !errors.Is(got.err, context.DeadlineExceeded) || got.response.Output != nil {
		t.Fatalf("deadline: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusCancelling {
		t.Fatalf("missing stop confirmation was fabricated: %s", run.Status)
	}
	if f.gateway.invokes.Load() != 1 || f.gateway.resumes.Load() != 0 {
		t.Fatal("timeout replayed business work")
	}
}

func TestSynchronousExplicitParentCancelStopsWaitingChild(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	var aborted atomic.Bool
	f.module.SetSynchronousRunAbortCheck(func(context.Context, sharedkernel.Scope) (bool, error) { return aborted.Load(), nil })
	ctx, cancel := context.WithCancel(context.Background())
	result := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	aborted.Store(true)
	cancel()
	if got := <-result; !errors.Is(got.err, context.Canceled) {
		t.Fatalf("cancel: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusCancelling {
		t.Fatalf("explicit cancellation did not request child stop: %s", run.Status)
	}
}

func TestSynchronousWorkerExitWithUnavailableParentKeepsWaitingHistory(t *testing.T) {
	f := newSynchronousReviewFixture(t)
	f.module.SetSynchronousRunAbortCheck(func(context.Context, sharedkernel.Scope) (bool, error) {
		return false, errors.New("parent store unavailable")
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := f.invoke(ctx)
	f.waitForStatus(t, platformruntime.StatusWaiting)
	cancel()
	if got := <-result; !errors.Is(got.err, context.Canceled) {
		t.Fatalf("exit: %+v", got)
	}
	run, _ := f.store.Get(f.scope.RunID)
	if run.Status != platformruntime.StatusWaiting {
		t.Fatal("unknown parent state was treated as explicit abort")
	}
}
