package agentgateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/contract"
)

func testScope() contract.ScopeKey {
	return contract.ScopeKey{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentInstanceID: "install", InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "user", SessionID: "session", RunID: "run", AuthorizationEpoch: 1, TraceID: "0123456789abcdef0123456789abcdef"}
}

func testRequest(operation string) contract.ExecuteRequest {
	return contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, ContextToken: "01234567890123456789012345678901", Scope: testScope(), Operation: operation, IdempotencyKey: "idem-1234", InputSchema: "schema://qa/input", Input: map[string]any{"question": "x"}}
}

type handlerStub struct{ called string }

func (h *handlerStub) Execute(_ context.Context, operation string, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	h.called = operation
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "accepted"}, nil
}
func (h *handlerStub) Events(context.Context, contract.EventRequest) (EventStream, error) {
	return EventStream{}, nil
}

type remoteStub struct{ delay time.Duration }

func (r remoteStub) response(request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	return contract.ExecuteResponse{ProtocolVersion: contract.ProtocolVersion, RunID: request.Scope.RunID, Status: "succeeded"}, nil
}
func (r remoteStub) Invoke(_ context.Context, _ Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return r.response(request)
}
func (r remoteStub) Run(_ context.Context, _ Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return r.response(request)
}
func (r remoteStub) Resume(_ context.Context, _ Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return r.response(request)
}
func (r remoteStub) Cancel(_ context.Context, _ Target, request contract.ExecuteRequest) (contract.ExecuteResponse, error) {
	return r.response(request)
}
func (r remoteStub) Events(context.Context, Target, contract.EventRequest) (EventStream, error) {
	return EventStream{}, nil
}

func TestLocalAdapterKeepsScopeAndOperationBoundary(t *testing.T) {
	stub := &handlerStub{}
	target := Target{InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", Transport: "local", Revision: 1, ManifestHash: "manifest"}
	out, err := (LocalAdapter{Handler: stub}).Run(context.Background(), target, testRequest("run"))
	if err != nil || out.Status != "accepted" || stub.called != "run" {
		t.Fatalf("local adapter result: out=%+v called=%q err=%v", out, stub.called, err)
	}
	bad := testRequest("run")
	bad.Scope.AgentID = "other"
	if _, err = (LocalAdapter{Handler: stub}).Run(context.Background(), target, bad); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("expected scope mismatch, got %v", err)
	}
}

func TestRemoteAdapterValidatesTargetAndDeadline(t *testing.T) {
	target := Target{InstallationID: "install", AgentID: "qa", AgentVersionID: "v1", Endpoint: "https://qa.example", Transport: "https", Revision: 1, ManifestHash: "manifest"}
	adapter := RemoteAdapter{Transport: remoteStub{}, Timeout: time.Second}
	out, err := adapter.Invoke(context.Background(), target, testRequest("invoke"))
	if err != nil || out.Status != "succeeded" {
		t.Fatalf("remote adapter result: out=%+v err=%v", out, err)
	}
	slow := RemoteAdapter{Transport: remoteStub{delay: 20 * time.Millisecond}, Timeout: time.Millisecond}
	if _, err = slow.Run(context.Background(), target, testRequest("run")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	badTarget := target
	badTarget.Transport = "local"
	if _, err = adapter.Run(context.Background(), badTarget, testRequest("run")); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("expected invalid target, got %v", err)
	}
}
