package execution

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type dispatcherGatewayStub struct {
	invoked bool
	resumed bool
	token   string
}

func TestGatewayDispatchSignsTokenFreeDurableCommandAfterAuthorization(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(map[bool]string{true: "authorized", false: "revoked"}[allowed], func(t *testing.T) {
			scope := testScope("token-free")
			var request contract.ExecuteRequest
			if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
				t.Fatal(err)
			}
			request.ContextToken = ""
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			store := platformruntime.NewStore()
			created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "token-free-command", Fingerprint: "fp", RequestJSON: raw, AgentEndpoint: "http://agent.example"})
			if err != nil {
				t.Fatal(err)
			}
			gateway := &dispatcherGatewayStub{}
			d := NewDispatcherWithGateway(store, "secret", gateway, 1)
			d.stopQuiescence = func(context.Context, sharedkernel.Scope) error { return nil }
			signed := 0
			d.SetSecurity(machineRunContextSignerFunc(func(_ context.Context, _ sharedkernel.Scope, r contract.ExecuteRequest) (string, error) {
				signed++
				if r.ContextToken != "" || r.Operation != "invoke" {
					t.Error("signer received a persisted token or wrong operation")
				}
				return "fresh-governed-context-token-000000000000000000000000", nil
			}), func(context.Context, sharedkernel.Scope) error {
				if !allowed {
					return errors.New("revoked")
				}
				return nil
			})
			if err := d.dispatch(context.Background(), created.Run); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(scope.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if allowed {
				if got.Status != platformruntime.StatusSucceeded || !gateway.invoked || signed != 1 || gateway.token == "" {
					t.Fatalf("signed dispatch failed: status=%s invoked=%v signs=%d", got.Status, gateway.invoked, signed)
				}
			} else if got.Status != platformruntime.StatusFailed || gateway.invoked || signed != 0 {
				t.Fatal("revoked command was signed or dispatched")
			}
			var persisted contract.ExecuteRequest
			if json.Unmarshal(got.RequestJSON, &persisted) != nil || persisted.ContextToken != "" {
				t.Fatal("transient bearer token was persisted")
			}
		})
	}
}

type retryingGatewayStub struct {
	invocations int
}

type statusMatrixGateway struct {
	status      string
	invocations int
	cancels     int
}

func statusMatrixResponse(runID, status string) contract.ExecuteResponse {
	response := contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: runID, Status: status}
	if status == "failed" {
		response.Error = &contract.AppError{Code: "FIXTURE_EXECUTION_FAILED", Message: "terminal fixture failure"}
	}
	return response
}

func (g *statusMatrixGateway) Invoke(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.invocations++
	return statusMatrixResponse(request.Scope.RunID, g.status), nil
}
func (g *statusMatrixGateway) Resume(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(context.Background(), agentgateway.Target{}, request)
}
func (g *statusMatrixGateway) Cancel(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.cancels++
	return statusMatrixResponse(request.Scope.RunID, "cancelled"), nil
}

// A synchronous Invoke may wait or truly terminate; accepted/running/empty
// cannot be silently promoted to success and require a signed stop ACK.
// 同步调用只能等待或真实终结；accepted/running/空状态必须签名停止，不能冒充成功。
func TestGatewayDispatchRejectsNonTerminalStatusMatrix(t *testing.T) {
	for _, item := range []struct {
		status string
		want   platformruntime.Status
		stop   bool
	}{
		{"accepted", platformruntime.StatusCancelled, true},
		{"running", platformruntime.StatusCancelled, true},
		{"", platformruntime.StatusCancelled, true},
		{"waiting", platformruntime.StatusWaiting, false},
		{"succeeded", platformruntime.StatusSucceeded, false},
		{"failed", platformruntime.StatusFailed, false},
		{"cancelled", platformruntime.StatusCancelled, false},
	} {
		name := item.status
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			scope := testScope("matrix-" + name)
			store := platformruntime.NewStore()
			created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "idem-" + name, Fingerprint: "fp", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example"})
			if err != nil {
				t.Fatal(err)
			}
			gateway := &statusMatrixGateway{status: item.status}
			d := NewDispatcherWithGateway(store, "secret", gateway, 1)
			d.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
				return "fresh-governed-context-token-000000000000000000000000", nil
			}), func(context.Context, sharedkernel.Scope) error { return nil })
			// This fixture only returns envelopes: it has no model or tool effects.
			// Signed dispatch still needs a scoped effect-authority response.
			d.stopQuiescence = func(_ context.Context, owner sharedkernel.Scope) error {
				if owner != scope.domain() {
					return errors.New("fixture effect scope mismatch")
				}
				return nil
			}
			if err := d.dispatch(context.Background(), created.Run); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(scope.RunID)
			if err != nil || got.Status != item.want {
				t.Fatalf("status=%+v err=%v", got, err)
			}
			if gateway.invocations != 1 {
				t.Fatalf("Agent invoked %d times", gateway.invocations)
			}
			wantStops := 0
			if item.stop {
				wantStops = 1
			}
			if gateway.cancels != wantStops {
				t.Fatalf("signed stop calls=%d want=%d", gateway.cancels, wantStops)
			}
			events, err := store.Events(scope.RunID, 0)
			if err != nil {
				t.Fatal(err)
			}
			completed := 0
			for _, event := range events {
				if event.Type == "task_completed" {
					completed++
				}
			}
			if item.status == "succeeded" && completed != 1 || item.status != "succeeded" && completed != 0 {
				t.Fatalf("nonterminal status produced success event: %+v", events)
			}
		})
	}
}

func (s *retryingGatewayStub) Invoke(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	s.invocations++
	if s.invocations == 1 {
		failure, err := agentgateway.NewCompletedExecutionFailure(contract.ExecuteResponse{
			ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "failed",
			Error: &contract.AppError{Code: "UPSTREAM_UNAVAILABLE", Message: "try again", Retryable: true},
		})
		if err != nil {
			return contract.ExecuteResponse{}, err
		}
		return contract.ExecuteResponse{}, failure
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}

func (s *retryingGatewayStub) Resume(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}

func (s *dispatcherGatewayStub) Invoke(_ context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	s.invoked = true
	s.token = request.ContextToken
	if target.InstallationID != "install" || target.AgentID != "agent" || target.AgentVersionID != "v1" || target.Transport != "http" {
		return contract.ExecuteResponse{}, agentgateway.ErrTargetMismatch
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}

func (s *dispatcherGatewayStub) Resume(_ context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	s.resumed = true
	s.token = request.ContextToken
	if request.ResumeInput["approved"] != true || target.InstallationID != "install" {
		return contract.ExecuteResponse{}, agentgateway.ErrTargetMismatch
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}

func gatewayRequest(t *testing.T, scope scopeDTO, operation string) []byte {
	t.Helper()
	request := contract.ExecuteRequest{
		ProtocolVersion: contract.ProtocolVersion,
		ContextToken:    "0123456789012345678901234567890123456789012345678901234567890123",
		Scope: contract.ScopeKey{
			TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
			PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID,
			InstallationID: scope.InstallationID,
			RunID:          scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID,
		},
		Operation:      operation,
		IdempotencyKey: "gateway-idempotency",
		InputSchema:    "schema://agent/input/v1",
		Input:          map[string]any{"policy_snapshot": map[string]any{"content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDispatcherUsesAgentGatewayPortForProductionDispatch(t *testing.T) {
	scope := testScope("gateway-dispatch")
	repository := platformruntime.NewStore()
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "gateway-dispatch", Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "gateway-idem",
		Fingerprint: "gateway-fingerprint", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := &dispatcherGatewayStub{}
	if err := NewDispatcherWithGateway(repository, "secret", stub, 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if !stub.invoked {
		t.Fatal("dispatcher bypassed AgentGateway Port")
	}
	final, err := repository.Get(created.Run.ID)
	if err != nil || final.Status != platformruntime.StatusSucceeded {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

func TestDispatcherUsesGatewayPortForDurableResumeInput(t *testing.T) {
	scope := testScope("gateway-resume")
	repository := platformruntime.NewStore()
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "gateway-resume", Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "gateway-resume-idem",
		Fingerprint: "gateway-resume-fingerprint", RequestJSON: gatewayRequest(t, scope, "run"), AgentEndpoint: "http://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.AcquireLease(created.Run.ID, "lease", time.Now().UTC(), dispatcherLeaseTTL); err != nil {
		t.Fatal(err)
	}
	// Use the normal transition path so the dispatcher receives a running Run.
	running, err := repository.Transition(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, created.Run.Revision+1)
	if err != nil {
		t.Fatal(err)
	}
	// A waiting Run with durable approval input is what the platform resume path
	// hands to the dispatcher after PrepareResume.
	if _, err = repository.Transition(running.ID, platformruntime.StatusRunning, platformruntime.StatusWaiting, running.Revision); err != nil {
		t.Fatal(err)
	}
	resumed, err := repository.PrepareResume(running.ID, []byte(`{"approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	stub := &dispatcherGatewayStub{}
	if err := NewDispatcherWithGateway(repository, "secret", stub, 1).dispatch(context.Background(), resumed); err != nil {
		t.Fatal(err)
	}
	if !stub.resumed {
		t.Fatal("dispatcher did not use Gateway resume operation")
	}
	final, err := repository.Get(resumed.ID)
	if err != nil || final.Status != platformruntime.StatusSucceeded {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

func TestGatewayDispatcherRetriesRetryableAppError(t *testing.T) {
	scope := testScope("gateway-retry")
	repository := platformruntime.NewStore()
	raw := gatewayRequest(t, scope, "run")
	request := contract.ExecuteRequest{}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	// Runtime policy is read from the durable request snapshot, so this test
	// exercises the same retry path used by the production Gateway dispatcher.
	request.Input["policy_snapshot"].(map[string]any)["runtime"] = map[string]any{"max_attempts": 2, "task_timeout_seconds": 5, "lease_seconds": 30}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: "gateway-retry", Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "gateway-retry-idem",
		Fingerprint: "gateway-retry-fingerprint", RequestJSON: raw, AgentEndpoint: "http://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	stub := &retryingGatewayStub{}
	if err := NewDispatcherWithGateway(repository, "secret", stub, 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if stub.invocations != 2 {
		t.Fatalf("retryable AppError should be retried once, calls=%d", stub.invocations)
	}
	final, err := repository.Get(created.Run.ID)
	if err != nil || final.Status != platformruntime.StatusSucceeded {
		t.Fatalf("final=%+v err=%v", final, err)
	}
}

func TestClassifyDispatchFailureHonorsRetryableAppError(t *testing.T) {
	code, retryable := classifyDispatchFailure(0, contract.AppError{Code: "UPSTREAM_UNAVAILABLE", Retryable: true})
	if code != "UPSTREAM_UNAVAILABLE" || !retryable {
		t.Fatalf("classification=%q/%v", code, retryable)
	}
}

type deadlineRetryGateway struct {
	retryingGatewayStub
	deadlines []time.Time
}

func (g *deadlineRetryGateway) Invoke(ctx context.Context, target agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return contract.ExecuteResponse{}, contract.AppError{Code: "DEADLINE_MISSING"}
	}
	g.deadlines = append(g.deadlines, deadline)
	return g.retryingGatewayStub.Invoke(ctx, target, request)
}

func TestGatewayRetriesSharePublishedTaskDeadline(t *testing.T) {
	scope := testScope("gateway-shared-deadline")
	repository := platformruntime.NewStore()
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
		t.Fatal(err)
	}
	request.Input["policy_snapshot"].(map[string]any)["runtime"] = map[string]any{"max_attempts": 2, "task_timeout_seconds": 5, "lease_seconds": 30}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	created, err := repository.Create(platformruntime.CreateRequest{
		ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "shared-deadline-idem",
		Fingerprint: "shared-deadline-fingerprint", RequestJSON: raw, AgentEndpoint: "http://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &deadlineRetryGateway{}
	if err := NewDispatcherWithGateway(repository, "secret", gateway, 1).dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	if len(gateway.deadlines) != 2 || !gateway.deadlines[0].Equal(gateway.deadlines[1]) {
		t.Fatal("retry extended the published task deadline")
	}
	final, err := repository.Get(created.Run.ID)
	if err != nil || final.Status != platformruntime.StatusSucceeded {
		t.Fatal("bounded retry did not finalize its actual outcome", err)
	}
}

type failingDomainGateway struct {
	dispatcherGatewayStub
	failure contract.AppError
	calls   int
}

type unprovedRetryGateway struct {
	dispatcherGatewayStub
	calls int
}

func (g *unprovedRetryGateway) Invoke(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.calls++
	return contract.ExecuteResponse{}, contract.AppError{Code: "UPSTREAM_UNAVAILABLE", Message: "unproved error", Retryable: true}
}

func TestGatewayDoesNotReplayUnprovedOrUnsettledFailures(t *testing.T) {
	for _, mode := range []string{"bare-app-error", "terminal-with-unknown-effect"} {
		t.Run(mode, func(t *testing.T) {
			scope := testScope("gateway-unproved-" + mode)
			store := platformruntime.NewStore()
			var request contract.ExecuteRequest
			if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
				t.Fatal(err)
			}
			request.Input["policy_snapshot"].(map[string]any)["runtime"] = map[string]any{"max_attempts": 2, "task_timeout_seconds": 5, "lease_seconds": 30}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "no-replay", Fingerprint: "no-replay-fingerprint", RequestJSON: raw, AgentEndpoint: "http://agent.example"})
			if err != nil {
				t.Fatal(err)
			}
			bare := &unprovedRetryGateway{}
			terminal := &failingDomainGateway{failure: contract.AppError{Code: "UPSTREAM_UNAVAILABLE", Retryable: true}}
			var gateway agentGateway = bare
			if mode == "terminal-with-unknown-effect" {
				gateway = terminal
			}
			dispatcher := NewDispatcherWithGateway(store, "secret", gateway, 1)
			dispatcher.stopQuiescence = func(context.Context, sharedkernel.Scope) error {
				return errors.New("authoritative effect still unknown")
			}
			if err := dispatcher.dispatch(context.Background(), created.Run); err != nil {
				t.Fatal(err)
			}
			current, err := store.Get(created.Run.ID)
			if err != nil || current.Status != platformruntime.StatusCancelling || bare.calls+terminal.calls != 1 {
				t.Fatal("unproved failure replayed or released FIFO before stop confirmation", err)
			}
		})
	}
}

func (g *failingDomainGateway) Invoke(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.calls++
	fault := g.failure
	if fault.Message == "" {
		fault.Message = "known terminal fixture failure"
	}
	failure, err := agentgateway.NewCompletedExecutionFailure(contract.ExecuteResponse{
		ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "failed", Error: &fault,
	})
	if err != nil {
		return contract.ExecuteResponse{}, err
	}
	return contract.ExecuteResponse{}, failure
}

// Check real dispatch and durable outcome, not just the classifier helper.
// 检查真实调度和持久化结果，不只测试错误分类辅助函数。
func TestGatewayFailurePreservesFinalDomainCode(t *testing.T) {
	for _, failure := range []contract.AppError{
		{Code: "RULE_BUNDLE_INVALID"}, {Code: "UNSUPPORTED_REPORT_TYPE"},
		{Code: "POLICY_DENIED"}, {Code: "CAPABILITY_UNAVAILABLE", Retryable: true},
	} {
		t.Run(failure.Code, func(t *testing.T) {
			scope := testScope("exact-final-error")
			store := platformruntime.NewStore()
			var request contract.ExecuteRequest
			if err := json.Unmarshal(gatewayRequest(t, scope, "run"), &request); err != nil {
				t.Fatal(err)
			}
			request.Input["policy_snapshot"].(map[string]any)["runtime"] = map[string]any{"max_attempts": 2, "task_timeout_seconds": 5, "lease_seconds": 30}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "exact-final", Fingerprint: "fp", RequestJSON: raw, AgentEndpoint: "http://agent.example"})
			if err != nil {
				t.Fatal(err)
			}
			gateway := &failingDomainGateway{failure: failure}
			if err := NewDispatcherWithGateway(store, "secret", gateway, 1).dispatch(context.Background(), created.Run); err != nil {
				t.Fatal(err)
			}
			outcome, err := store.GetOutcome(scope.RunID)
			if err != nil || outcome.EventType != "task_failed" || outcome.EventPayload["code"] != failure.Code {
				t.Fatalf("outcome=%+v err=%v", outcome, err)
			}
			wantCalls := 1
			if failure.Retryable {
				wantCalls = 2
			}
			if gateway.calls != wantCalls {
				t.Fatalf("calls=%d want=%d", gateway.calls, wantCalls)
			}
			events, err := store.Events(scope.RunID, 0)
			if err != nil {
				t.Fatal(err)
			}
			attempts := 0
			for _, event := range events {
				if event.Type == "attempt_failed" {
					attempts++
					if event.Payload["code"] != failure.Code || event.Payload["retryable"] != failure.Retryable {
						t.Fatalf("event=%+v", event)
					}
				}
			}
			if attempts != wantCalls {
				t.Fatalf("attempts=%d want=%d", attempts, wantCalls)
			}
		})
	}
}
