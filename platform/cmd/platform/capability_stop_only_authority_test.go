package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type stopOnlyAuthorityExecution struct {
	leaseChecked bool
	action       string
}

func (e *stopOnlyAuthorityExecution) ValidateLiveLease(ctx context.Context, _ sharedkernel.Scope, operation, bodyHash, policyHash string) error {
	lease, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
	e.leaseChecked = ok && lease.Revision == 7 && lease.TokenHash == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if operation != "run" || bodyHash != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || policyHash != "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" || !e.leaseChecked {
		return errors.New("exact signed lease command missing")
	}
	return nil
}

func (*stopOnlyAuthorityExecution) RenewCapabilityToken(context.Context, sharedkernel.Scope, string, string, string) (string, error) {
	return "", errors.New("unused")
}

func (e *stopOnlyAuthorityExecution) CapabilityAuthorizationAction(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) (string, error) {
	if operation != "run" {
		return "", errors.New("not the persisted run operation")
	}
	if err := e.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
		return "", err
	}
	return e.action, nil
}

type stopOnlyAuthorityIAM struct{ epoch uint64 }

func (i stopOnlyAuthorityIAM) CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error) {
	return i.epoch, nil
}

type stopOnlyAuthorityCatalog struct{ expected sharedkernel.Scope }

func (c stopOnlyAuthorityCatalog) ResolveEvaluationAgentTarget(_ context.Context, scope sharedkernel.Scope, agentID, versionID string) (catalog.EvaluationAgentTarget, error) {
	if scope.TenantID != c.expected.TenantID || scope.InstallationID != c.expected.InstallationID || agentID != c.expected.AgentID || versionID != c.expected.AgentVersionID {
		return catalog.EvaluationAgentTarget{}, errors.New("target mismatch")
	}
	return catalog.EvaluationAgentTarget{InstallationID: scope.InstallationID, AgentVersionID: versionID}, nil
}

func TestStopOnlyCapabilityRequiresCurrentGenerationButNotRenewedIAMEpoch(t *testing.T) {
	scope := sharedkernel.Scope{
		TenantID: "tenant", DepartmentID: "department", ApplicationID: "application",
		AgentInstanceID: "installation", InstallationID: "installation", AgentID: "agent",
		AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "caller", SessionID: "session",
		RunID: "parent-run", AuthorizationEpoch: 4, TraceID: "0123456789abcdef0123456789abcdef",
	}
	execution := &stopOnlyAuthorityExecution{action: "run"}
	authority := capabilityExecutionAuthority{execution: execution, identity: stopOnlyAuthorityIAM{epoch: 5}, catalog: stopOnlyAuthorityCatalog{expected: scope}}
	lease := sharedkernel.ExecutionLeaseBinding{Revision: 7, TokenHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := authority.AuthorizeStopOnlyExecution(context.Background(), scope, "run", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", lease); err != nil {
		t.Fatalf("stop-only was blocked by a later IAM epoch despite the signed live Run generation: %v", err)
	}
	if !execution.leaseChecked {
		t.Fatal("stop-only did not require the exact current parent lease")
	}

	if err := authority.AuthorizeCapability(context.Background(), scope, "run", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"); err == nil {
		t.Fatal("ordinary execution remained allowed after current IAM epoch changed")
	}
	if err := authority.AuthorizeStopOnlyExecution(context.Background(), scope, "resume", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", lease); err == nil {
		t.Fatal("stop-only accepted a non-run action")
	}
	if err := authority.AuthorizeStopOnlyExecution(context.Background(), scope, "run", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", sharedkernel.ExecutionLeaseBinding{Revision: 0, TokenHash: lease.TokenHash}); err == nil {
		t.Fatal("stop-only accepted a missing current lease revision")
	}
}

var _ identity.AuthorizationVersionPort = stopOnlyAuthorityIAM{}
