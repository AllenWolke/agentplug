package execution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
)

type cancelTestGateway struct {
	fail     bool
	calls    int
	observed contract.ExecuteRequest
}

func (g *cancelTestGateway) Invoke(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{}, errors.New("unexpected invoke")
}
func (g *cancelTestGateway) Resume(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return contract.ExecuteResponse{}, errors.New("unexpected resume")
}
func (g *cancelTestGateway) Cancel(_ context.Context, _ agentgateway.Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.calls++
	g.observed = request
	if g.fail {
		return contract.ExecuteResponse{}, errors.New("offline")
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "cancelled"}, nil
}

func TestSignedCancellationRecoveryReleasesSessionOnlyAfterStopAck(t *testing.T) {
	cancellationFailures := func() uint64 {
		t.Helper()
		out := httptest.NewRecorder()
		telemetry.MetricsHandler().ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		const prefix = "agent_execution_reconciliation_failures_total{stage=\"cancellation\"} "
		for _, line := range strings.Split(out.Body.String(), "\n") {
			if strings.HasPrefix(line, prefix) {
				value, err := strconv.ParseUint(strings.TrimPrefix(line, prefix), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
		}
		t.Fatal("cancellation failure metric missing")
		return 0
	}
	failuresBefore := cancellationFailures()
	store := platformruntime.NewStore()
	scope := testScope("signed-cancel").domain()
	wire := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, InstallationID: scope.InstallationID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID}
	request := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, ContextToken: "expired-is-not-reused", Scope: wire, Operation: "invoke", IdempotencyKey: "signed-cancel-idem", InputSchema: "schema://test/input/v1", Input: map[string]any{"policy_snapshot": map[string]any{"content_hash": strings.Repeat("a", 64)}}}
	raw, _ := json.Marshal(request)
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope, AgentVersionID: scope.AgentVersionID, IdempotencyKey: "signed-cancel-idem", Fingerprint: "fixture", RequestJSON: raw, AgentEndpoint: "http://agent.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.AcquireLease(created.Run.ID, "worker", time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.TransitionLeased(created.Run.ID, platformruntime.StatusAccepted, platformruntime.StatusRunning, claimed.Revision, claimed.LeaseToken)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordDispatchCommand(platformruntime.DispatchCommand{RunID: running.ID, Revision: running.Revision, Operation: request.Operation, BodyHash: bodyHash, PolicyHash: strings.Repeat("a", 64)}, running.LeaseToken); err != nil {
		t.Fatal(err)
	}
	gateway := &cancelTestGateway{fail: true}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(ctx context.Context, s sharedkernel.Scope, r contract.ExecuteRequest) (string, error) {
		binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
		if !ok || binding.Revision != running.Revision || s != scope || r.Operation != "cancel" || r.ContextToken != "" || r.ResumeInput != nil {
			t.Fatal("cancel is not bound to original generation")
		}
		return "fresh-signed-stop-control", nil
	}), func(context.Context, sharedkernel.Scope) error {
		t.Fatal("business grant must not prevent stop after revocation")
		return nil
	})
	module := NewModuleWithDispatcher("", store, dispatcher)
	pending, err := module.requestCancellation(context.Background(), running, running.Revision)
	if err != nil || pending.Status != platformruntime.StatusCancelling {
		t.Fatalf("offline stop was falsely finalized: %+v %v", pending, err)
	}
	if cancellationFailures() != failuresBefore+1 {
		t.Fatal("failed signed cancellation did not increment recovery failure metric")
	}
	if gateway.calls != 1 || gateway.observed.ContextToken != "fresh-signed-stop-control" {
		t.Fatal("persisted stale token reused")
	}
	if lenRuns, err := store.PendingCancellations(16); err != nil || len(lenRuns) != 1 {
		t.Fatal("cancel intent was lost")
	}
	// A new Dispatcher after restart handles intent without invoking the Agent.
	// 重启后的 Dispatcher 只重投停止命令，不重跑模型或业务图。
	gateway.fail = false
	restarted := NewDispatcherWithGateway(store, "", gateway, 1)
	restarted.SetSecurity(dispatcher.signer, nil)
	settled := false
	restartedModule := NewModuleWithDispatcher("", store, restarted)
	restartedModule.SetStopQuiescence(func(_ context.Context, owner sharedkernel.Scope) error {
		if owner != scope || gateway.calls < 2 {
			t.Fatal("model barrier not bound to owner after remote stop")
		}
		if !settled {
			return errors.New("provider billing unresolved")
		}
		return nil
	})
	restarted.reconcileCancellations(context.Background())
	stillPending, err := store.Get(running.ID)
	if err != nil || stillPending.Status != platformruntime.StatusCancelling || stillPending.Revision != pending.Revision || stillPending.LeaseToken != pending.LeaseToken {
		t.Fatal("remote exit released run before model settlement", err)
	}
	if _, err := store.GetOutcome(running.ID); !errors.Is(err, platformruntime.ErrRunNotFound) {
		t.Fatal("unsettled cancellation fabricated terminal output")
	}
	if _, err := store.AcquireLease(running.ID, "competing-owner", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("unsettled model allowed lease reuse")
	}
	settled = true
	restarted.reconcileCancellations(context.Background())
	final, err := store.Get(running.ID)
	if err != nil || final.Status != platformruntime.StatusCancelled || final.LeaseToken != "" || gateway.calls != 3 {
		t.Fatalf("stop ACK not finalized: %+v %v", final, err)
	}
	outcome, err := store.GetOutcome(running.ID)
	if err != nil || outcome.Revision != final.Revision || outcome.EventType != "task_cancelled" || string(outcome.OutputJSON) != "{}" {
		t.Fatalf("cancelled response not durably saved: %+v %v", outcome, err)
	}
}
