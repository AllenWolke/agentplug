package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type synchronousCountingGateway struct{ calls atomic.Int32 }

type synchronousFailureGateway struct{ calls atomic.Int32 }

func (g *synchronousFailureGateway) Invoke(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.calls.Add(1)
	// Model the actual gateway contract: a failed remote execution is replayable
	// only when the v2 response binds a terminal failure to this exact Run.
	failure, err := agentgateway.NewCompletedExecutionFailure(contract.ExecuteResponse{
		ProtocolVersion: contract.ProtocolVersion,
		RunID:           request.Scope.RunID,
		Status:          "failed",
		Error:           &contract.AppError{Code: "RULE_BUNDLE_INVALID", Message: "invalid governed release", Retryable: false},
	})
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return contract.ExecuteResponse{}, failure
}
func (g *synchronousFailureGateway) Resume(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{}, errors.New("unexpected resume")
}

func (g *synchronousCountingGateway) Invoke(ctx context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.calls.Add(1)
	select {
	case <-ctx.Done():
		return contract.ExecuteResponse{}, ctx.Err()
	case <-time.After(20 * time.Millisecond):
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded", Output: map[string]any{"answer": "persisted case"}}, nil
}
func (g *synchronousCountingGateway) Resume(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{}, errors.New("unexpected resume")
}

func TestSynchronousParentedRunNeedsEvaluationAdmissionBeforePersistence(t *testing.T) {
	store := platformruntime.NewStore()
	gateway := &synchronousCountingGateway{}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-governed-context-token-000000000000000000000000", nil
	}), func(context.Context, sharedkernel.Scope) error { return nil })
	module := NewModuleWithDispatcherAndSharedRepository("", store, dispatcher)
	scope := testScope("evaluation-child").domain()
	scope.ParentRunID = "evaluation-product-run"
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, testScope(scope.RunID), "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	request.Scope.ParentRunID = scope.ParentRunID
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := module.InvokeSynchronous(ctx, scope, "http://agent.example", request); !errors.Is(err, contract.ErrPermissionDenied) {
		t.Fatalf("parented Run without Evaluation admission was not denied: %v", err)
	}
	if _, err := store.Get(scope.RunID); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatalf("denied admission persisted a child Run: %v", err)
	}
	if gateway.calls.Load() != 0 {
		t.Fatal("denied Evaluation admission reached the Agent")
	}
}

func TestSynchronousEvaluationAdmissionRunsBeforeCreateAndKeepsRootPath(t *testing.T) {
	store := platformruntime.NewStore()
	gateway := &synchronousCountingGateway{}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-governed-context-token-000000000000000000000000", nil
	}), func(context.Context, sharedkernel.Scope) error { return nil })
	module := NewModuleWithDispatcherAndSharedRepository("", store, dispatcher)
	scope := testScope("evaluation-child").domain()
	scope.ParentRunID = "evaluation-product-run"
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, testScope(scope.RunID), "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	request.Scope.ParentRunID = scope.ParentRunID
	called := false
	module.SetSynchronousRunAuthorizer(func(_ context.Context, gotScope sharedkernel.Scope, endpoint string, gotRequest contract.ExecuteRequest) error {
		if gotScope != scope || endpoint != "http://agent.example" || gotRequest.Scope != request.Scope {
			return errors.New("admission request scope mismatch")
		}
		if _, err := store.Get(scope.RunID); !called && !errors.Is(err, platformruntime.ErrRunNotFound) {
			return errors.New("admission ran after child persistence")
		}
		called = true
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if response, err := module.InvokeSynchronous(ctx, scope, "http://agent.example", request); err != nil || response.Status != "succeeded" {
		t.Fatalf("admitted Evaluation invocation failed: response=%+v err=%v", response, err)
	}
	if !called || gateway.calls.Load() != 1 {
		t.Fatalf("pre-create verifier or governed Agent call missing: verifier=%v calls=%d", called, gateway.calls.Load())
	}
}

func TestSynchronousRunConcurrentReplayUsesOneGovernedInvocation(t *testing.T) {
	store := platformruntime.NewStore()
	gateway := &synchronousCountingGateway{}
	d := NewDispatcherWithGateway(store, "", gateway, 2)
	var revoked atomic.Bool
	d.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-governed-context-token-000000000000000000000000", nil
	}), func(context.Context, sharedkernel.Scope) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	})
	m := NewModuleWithDispatcherAndSharedRepository("", store, d)
	scope := testScope("case-run").domain()
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, testScope(scope.RunID), "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var callers sync.WaitGroup
	for i := 0; i < 8; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			result, err := m.InvokeSynchronous(ctx, scope, "http://agent.example", request)
			if err != nil || result.Status != "succeeded" || result.Output["answer"] != "persisted case" {
				t.Errorf("synchronous replay: %+v %v", result, err)
			}
		}()
	}
	callers.Wait()
	if gateway.calls.Load() != 1 {
		t.Fatalf("Agent rerun on concurrent replay: %d", gateway.calls.Load())
	}
	// New Module/Dispatcher reads the saved result without invoking the Agent.
	// 新 Module/Dispatcher 只读保存的响应，不再调用 Agent。
	restarted := NewDispatcherWithGateway(store, "", gateway, 1)
	restarted.SetSecurity(d.signer, d.authorize)
	newModule := NewModuleWithDispatcherAndSharedRepository("", store, restarted)
	if result, err := newModule.InvokeSynchronous(ctx, scope, "http://agent.example", request); err != nil || result.Output["answer"] != "persisted case" {
		t.Fatalf("restart replay lost result: %+v %v", result, err)
	}
	request.Input["question"] = "changed input"
	if _, err := newModule.InvokeSynchronous(ctx, scope, "http://agent.example", request); !errors.Is(err, platformruntime.ErrIdempotencyConflict) {
		t.Fatalf("changed input replay accepted: %v", err)
	}
	delete(request.Input, "question")
	revoked.Store(true)
	if _, err := newModule.InvokeSynchronous(ctx, scope, "http://agent.example", request); !errors.Is(err, contract.ErrPermissionDenied) {
		t.Fatalf("revoked replay accepted: %v", err)
	}
	if gateway.calls.Load() != 1 {
		t.Fatal("negative checks caused another invocation")
	}
}

// A persisted failed child Run is replayed after process reconstruction;
// evaluation recovery must not issue a second Agent or model invocation.
// 已落库的失败子 Run 在进程重建后回放，评测补偿不得再调用 Agent。
func TestSynchronousFailedChildRunReplaysAfterRestart(t *testing.T) {
	store := platformruntime.NewStore()
	gateway := &synchronousFailureGateway{}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	signer := machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-governed-context-token-000000000000000000000000", nil
	})
	authorize := func(context.Context, sharedkernel.Scope) error { return nil }
	dispatcher.SetSecurity(signer, authorize)
	module := NewModuleWithDispatcherAndSharedRepository("", store, dispatcher)
	scope := testScope("failed-child-run").domain()
	module.SetStopQuiescence(func(_ context.Context, owner sharedkernel.Scope) error {
		// This terminal-failure fixture never calls a model or tool provider.
		if owner != scope {
			return errors.New("fixture effect scope mismatch")
		}
		return nil
	})
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, testScope(scope.RunID), "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := module.InvokeSynchronous(ctx, scope, "http://agent.example", request)
	if err != nil || first.Status != "failed" || first.Error == nil || first.Error.Code != "RULE_BUNDLE_INVALID" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	restarted := NewDispatcherWithGateway(store, "", gateway, 1)
	restarted.SetSecurity(signer, authorize)
	second := NewModuleWithDispatcherAndSharedRepository("", store, restarted)
	replayed, err := second.InvokeSynchronous(ctx, scope, "http://agent.example", request)
	if err != nil || replayed.Status != "failed" || replayed.Error == nil || replayed.Error.Code != "RULE_BUNDLE_INVALID" {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	if gateway.calls.Load() != 1 {
		t.Fatalf("failed child Run reinvoked Agent %d times", gateway.calls.Load())
	}
}
