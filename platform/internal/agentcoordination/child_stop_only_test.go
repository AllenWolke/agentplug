package agentcoordination

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type childStopOnlyTestStore struct {
	called   int
	scope    sharedkernel.Scope
	request  ChildCancelRequest
	identity ChildStopIdentity
}

func (*childStopOnlyTestStore) Transact(context.Context, sharedkernel.Scope, func(RouteTransaction) error) error {
	return ErrUnavailable
}

func (s *childStopOnlyTestStore) CancelChildStopOnly(_ context.Context, scope sharedkernel.Scope, request ChildCancelRequest, identity ChildStopIdentity) (ChildCancellation, error) {
	s.called++
	s.scope, s.request, s.identity = scope, request, identity
	return ChildCancellation{Version: "agent-child-cancellation/v1", ParentRunID: scope.RunID, ChildRunID: "child-run", ChildKey: "child-key", OperationKey: request.OperationKey, Ordinal: request.Ordinal, Status: "cancelling", ExecutionRevision: request.ExpectedExecutionRevision + 1}, nil
}

func TestRouterStopOnlyRequiresTrustedGenerationAndPositiveCAS(t *testing.T) {
	store := &childStopOnlyTestStore{}
	router, err := NewRouter(store)
	if err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{
		TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
		AgentInstanceID: "parent-installation", InstallationID: "parent-installation",
		AgentID: "parent-agent", AgentVersionID: "parent-v1", PrincipalType: "user",
		PrincipalID: "caller", SessionID: "session", RunID: "parent-run",
		AuthorizationEpoch: 7, TraceID: "0123456789abcdef0123456789abcdef",
	}
	identity := ChildStopIdentity{
		Lease:              sharedkernel.ExecutionLeaseBinding{Revision: 9, TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PolicyHash:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		MachinePrincipalID: "parent-machine",
	}
	request := ChildCancelRequest{OperationKey: "operation-1", Ordinal: 0, ExpectedExecutionRevision: 4}
	result, err := router.CancelChildStopOnly(context.Background(), scope, request, identity)
	if err != nil {
		t.Fatalf("valid stop-only request denied: %v", err)
	}
	if result.Status != "cancelling" || store.called != 1 || store.scope != scope || store.request != request || store.identity != identity {
		t.Fatalf("stop-only request was not forwarded exactly once: result=%#v calls=%d", result, store.called)
	}

	badScope := scope
	badScope.AuthorizationEpoch = 0
	badIdentity := identity
	badIdentity.PolicyHash = "not-a-hash"
	tests := []struct {
		name     string
		scope    sharedkernel.Scope
		request  ChildCancelRequest
		identity ChildStopIdentity
	}{
		{name: "incomplete scope", scope: badScope, request: request, identity: identity},
		{name: "invalid parent lease", scope: scope, request: request, identity: ChildStopIdentity{Lease: sharedkernel.ExecutionLeaseBinding{Revision: 0, TokenHash: identity.Lease.TokenHash}, PolicyHash: identity.PolicyHash, MachinePrincipalID: identity.MachinePrincipalID}},
		{name: "invalid policy pin", scope: scope, request: request, identity: badIdentity},
		{name: "missing machine identity", scope: scope, request: request, identity: ChildStopIdentity{Lease: identity.Lease, PolicyHash: identity.PolicyHash}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := router.CancelChildStopOnly(context.Background(), test.scope, test.request, test.identity)
			if err == nil {
				t.Fatal("malformed stop-only identity or CAS was accepted")
			}
		})
	}
	if store.called != 1 {
		t.Fatalf("invalid requests reached the stop store: calls=%d", store.called)
	}
}
