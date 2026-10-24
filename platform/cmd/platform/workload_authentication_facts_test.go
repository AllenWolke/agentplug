package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type workloadFactsFixture struct {
	capabilitySnapshotFixture
	facts    map[identity.PrincipalType]identity.PrincipalPolicyFacts
	reads    int
	factsErr error
}

func (f *workloadFactsFixture) PrincipalPolicyFacts(_ context.Context, kind identity.PrincipalType, _ string) (identity.PrincipalPolicyFacts, error) {
	f.reads++
	return f.facts[kind], f.factsErr
}

func TestWorkloadAuthenticationReadsFreshNarrowFacts(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "u", PrincipalType: "user", SessionID: "s", RunID: "r", AuthorizationEpoch: 1, TraceID: "trace"}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	fullReads, credentials := 0, 0
	f := &workloadFactsFixture{capabilitySnapshotFixture: capabilitySnapshotFixture{binding: &binding, snapshotReads: &fullReads, credentialReads: &credentials}, facts: map[identity.PrincipalType]identity.PrincipalPolicyFacts{
		identity.PrincipalUser:             {ID: "u", Type: identity.PrincipalUser, TenantID: "t", IsActive: true, Mode: "v2"},
		identity.PrincipalServicePrincipal: {ID: "executor", Type: identity.PrincipalServicePrincipal, TenantID: "t", IsActive: true, Mode: "v2"},
	}}
	authority := capabilityExecutionAuthority{identity: f}
	auth := func() error {
		return authority.AuthenticateWorkload(context.Background(), scope, "executor", "workload-fixture-secret-value-12345678", "127.0.0.1:1234")
	}
	for range 2 {
		if err := auth(); err != nil {
			t.Fatal(err)
		}
	}
	if f.reads != 4 || fullReads != 0 || credentials != 2 {
		t.Fatalf("facts=%d full=%d credentials=%d", f.reads, fullReads, credentials)
	}
	executor := f.facts[identity.PrincipalServicePrincipal]
	executor.IsActive = false
	f.facts[identity.PrincipalServicePrincipal] = executor
	if !errors.Is(auth(), identity.ErrPermissionDenied) {
		t.Fatal("revoked executor reused")
	}
	executor.IsActive = true
	f.facts[identity.PrincipalServicePrincipal] = executor
	f.credentialDisabled = true
	if !errors.Is(auth(), identity.ErrPermissionDenied) {
		t.Fatal("revoked credential reused")
	}
	f.credentialDisabled = false
	binding.Status = "revoked"
	if !errors.Is(auth(), identity.ErrPermissionDenied) {
		t.Fatal("revoked binding reused")
	}
	binding.Status = "active"
	f.factsErr = identity.ErrPrincipalNotFound
	if !errors.Is(auth(), identity.ErrPrincipalNotFound) {
		t.Fatal("facts failure bypassed")
	}
}
