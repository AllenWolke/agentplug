package agentgateway

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/contract"
)

type recordingTransport struct {
	calls []string
	err   error
}

func (t *recordingTransport) Invoke(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	t.calls = append(t.calls, "invoke")
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: "run", Status: "succeeded"}, t.err
}
func (t *recordingTransport) Run(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	t.calls = append(t.calls, "run")
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: "run", Status: "succeeded"}, t.err
}
func (t *recordingTransport) Resume(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	t.calls = append(t.calls, "resume")
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: "run", Status: "succeeded"}, t.err
}
func (t *recordingTransport) Cancel(context.Context, Target, contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	t.calls = append(t.calls, "cancel")
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: "run", Status: "cancelled"}, t.err
}
func (t *recordingTransport) Events(context.Context, Target, contract.EventRequest) (EventStream, error) {
	t.calls = append(t.calls, "events")
	return EventStream{}, t.err
}

func TestRoutingTransportSelectsProtocolForEveryOperation(t *testing.T) {
	httpTransport, grpcTransport := &recordingTransport{}, &recordingTransport{}
	router := RoutingTransport{HTTP: httpTransport, GRPC: grpcTransport}
	httpTarget := Target{InstallationID: "install", AgentID: "agent", AgentVersionID: "v1", Endpoint: "https://agent.example", Transport: "https", Revision: 1, ManifestHash: "sha256:manifest"}
	grpcTarget := Target{InstallationID: "install", AgentID: "agent", AgentVersionID: "v1", Endpoint: "grpcs://agent.example:9443", Transport: "grpcs", Revision: 1, ManifestHash: "sha256:manifest"}
	request := contract.ExecuteRequest{}
	for _, operation := range []struct {
		name string
		call func(Target) error
	}{
		{name: "invoke", call: func(target Target) error { _, err := router.Invoke(context.Background(), target, request); return err }},
		{name: "run", call: func(target Target) error { _, err := router.Run(context.Background(), target, request); return err }},
		{name: "resume", call: func(target Target) error { _, err := router.Resume(context.Background(), target, request); return err }},
		{name: "cancel", call: func(target Target) error { _, err := router.Cancel(context.Background(), target, request); return err }},
	} {
		if err := operation.call(httpTarget); err != nil {
			t.Fatalf("HTTP %s dispatch: %v", operation.name, err)
		}
		if err := operation.call(grpcTarget); err != nil {
			t.Fatalf("gRPC %s dispatch: %v", operation.name, err)
		}
	}
	if _, err := router.Events(context.Background(), httpTarget, contract.EventRequest{}); err != nil {
		t.Fatalf("HTTP events dispatch: %v", err)
	}
	if _, err := router.Events(context.Background(), grpcTarget, contract.EventRequest{}); err != nil {
		t.Fatalf("gRPC events dispatch: %v", err)
	}
	wantHTTP := []string{"invoke", "run", "resume", "cancel", "events"}
	wantGRPC := append([]string(nil), wantHTTP...)
	if !equalCalls(httpTransport.calls, wantHTTP) || !equalCalls(grpcTransport.calls, wantGRPC) {
		t.Fatalf("transport selection mismatch: http=%v grpc=%v", httpTransport.calls, grpcTransport.calls)
	}
}

func TestRoutingTransportFailsClosedWithoutProtocolFallback(t *testing.T) {
	httpTransport := &recordingTransport{}
	router := RoutingTransport{HTTP: httpTransport}
	target := Target{InstallationID: "install", AgentID: "agent", AgentVersionID: "v1", Endpoint: "grpc://agent.example:9000", Transport: "grpc", Revision: 1, ManifestHash: "sha256:manifest"}
	if _, err := router.Invoke(context.Background(), target, contract.ExecuteRequest{}); !errors.Is(err, ErrNoAdapter) {
		t.Fatalf("missing gRPC adapter error = %v, want ErrNoAdapter", err)
	}
	if len(httpTransport.calls) != 0 {
		t.Fatalf("gRPC failure silently fell back to HTTP: %v", httpTransport.calls)
	}
	target.Endpoint = "https://agent.example"
	target.Transport = "https"
	router.GRPC = &recordingTransport{err: errors.New("gRPC transport failure")}
	if _, err := router.Invoke(context.Background(), target, contract.ExecuteRequest{}); err != nil {
		t.Fatalf("HTTP route should not be affected by gRPC adapter failure: %v", err)
	}
	if len(httpTransport.calls) != 1 || len(router.GRPC.(*recordingTransport).calls) != 0 {
		t.Fatalf("wrong adapter selected: http=%v grpc=%v", httpTransport.calls, router.GRPC.(*recordingTransport).calls)
	}
}

func equalCalls(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
