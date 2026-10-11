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

type uncertainGateway struct {
	invocations int
	stops       int
	confirm     bool
}

func (g *uncertainGateway) Invoke(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.invocations++
	// Timeout leaves an independently running remote node; no implicit stop.
	// 超时后远程节点可能仍在执行，不能把请求错误当作停止证明。
	return contract.ExecuteResponse{}, context.DeadlineExceeded
}
func (g *uncertainGateway) Resume(ctx context.Context, t agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return g.Invoke(ctx, t, r)
}
func (g *uncertainGateway) Cancel(_ context.Context, _ agentgateway.Target, r contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	g.stops++
	if !g.confirm {
		return contract.ExecuteResponse{}, errors.New("stop not confirmed")
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: r.Scope.RunID, Status: "cancelled"}, nil
}

func TestTimeoutDoesNotRetryOrReleaseSessionBeforeRemoteStop(t *testing.T) {
	store := platformruntime.NewStore()
	scope := testScope("unknown-running")
	var request contract.ExecuteRequest
	if err := json.Unmarshal(gatewayRequest(t, scope, "invoke"), &request); err != nil {
		t.Fatal(err)
	}
	request.Input["policy_snapshot"].(map[string]any)["runtime"] = map[string]any{"max_attempts": 3}
	raw, _ := json.Marshal(request)
	created, err := store.Create(platformruntime.CreateRequest{ID: scope.RunID, Scope: scope.domain(), AgentVersionID: "v1", IdempotencyKey: "unknown-execution", Fingerprint: "fixture", RequestJSON: raw, AgentEndpoint: "http://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &uncertainGateway{}
	dispatcher := NewDispatcherWithGateway(store, "", gateway, 1)
	dispatcher.SetSecurity(machineRunContextSignerFunc(func(context.Context, sharedkernel.Scope, contract.ExecuteRequest) (string, error) {
		return "fresh-token-for-control-command", nil
	}), func(context.Context, sharedkernel.Scope) error { return nil })
	if err := dispatcher.dispatch(context.Background(), created.Run); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Get(created.Run.ID)
	if err != nil || pending.Status != platformruntime.StatusCancelling || gateway.invocations != 1 || gateway.stops != 1 {
		t.Fatalf("timeout retried or finalized remote execution: %+v calls=%d/%d err=%v", pending, gateway.invocations, gateway.stops, err)
	}
	nextScope := scope.domain()
	nextScope.RunID = "unknown-next"
	next, err := store.Create(platformruntime.CreateRequest{ID: nextScope.RunID, Scope: nextScope, AgentVersionID: "v1", IdempotencyKey: "next", Fingerprint: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(next.Run.ID, "next-worker", time.Now().UTC().Add(time.Hour), time.Minute); !errors.Is(err, platformruntime.ErrLeaseConflict) {
		t.Fatal("unknown remote task released session")
	}
	events, err := store.Events(created.Run.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Type == "cancel_requested" && event.Payload["code"] == "AGENT_EXECUTION_TIMEOUT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("original timeout classification lost: %+v", events)
	}
	gateway.confirm = true
	dispatcher.reconcileCancellations(context.Background())
	final, err := store.Get(created.Run.ID)
	if err != nil || final.Status != platformruntime.StatusCancelled || gateway.invocations != 1 {
		t.Fatal("stop recovery replayed business invocation")
	}
	if _, err := store.AcquireLease(next.Run.ID, "next-worker", time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("stop ACK failed to release session")
	}
}
