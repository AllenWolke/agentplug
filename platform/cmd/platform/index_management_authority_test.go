package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type indexManagementExecutionFixture struct {
	delegatedExecutionFixture
	pinnedCalls int
	leaseErr    error
}

type combinedManagementExecutionFixture struct {
	indexManagementExecutionFixture
	combinedCalls, legacyCalls int
}

func (f *combinedManagementExecutionFixture) ValidateLiveLease(context.Context, sharedkernel.Scope, string, string, string) error {
	f.legacyCalls++
	return errors.New("duplicate legacy path must not run")
}
func (f *combinedManagementExecutionFixture) ValidateLiveLeaseAndAction(context.Context, sharedkernel.Scope, string, string, string) (string, error) {
	f.combinedCalls++
	return f.action, f.leaseErr
}

func TestCombinedAuthorityKeepsFreshIAMCatalogAndActionChecks(t *testing.T) {
	for _, mode := range []string{"management", "revoked", "lease-denied", "unknown-action", "foreign-target"} {
		t.Run(mode, func(t *testing.T) {
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "indexer", AgentInstanceID: "install", InstallationID: "install", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "manager", SessionID: "s", RunID: "index-root", AuthorizationEpoch: 1, TraceID: "trace"}
			ex := &combinedManagementExecutionFixture{indexManagementExecutionFixture: indexManagementExecutionFixture{delegatedExecutionFixture: delegatedExecutionFixture{action: "policy.manage"}}}
			id := capabilitySnapshotFixture{}
			target := catalog.EvaluationAgentTarget{AgentID: scope.AgentID, InstallationID: scope.InstallationID, AgentVersionID: scope.AgentVersionID}
			switch mode {
			case "revoked":
				id.failure = errors.New("revoked")
			case "lease-denied":
				ex.leaseErr = errors.New("lease denied")
			case "unknown-action":
				ex.action = "untrusted"
			case "foreign-target":
				target.InstallationID = "foreign"
			}
			a := capabilityExecutionAuthority{execution: ex, identity: id, catalog: delegatedCatalogFixture{target: target}}
			err := a.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy")
			if (err == nil) != (mode == "management") || ex.combinedCalls != 1 || ex.legacyCalls != 0 {
				t.Fatal(mode, err, ex.combinedCalls, ex.legacyCalls)
			}
		})
	}
}

func (f *indexManagementExecutionFixture) ValidateLiveLease(context.Context, sharedkernel.Scope, string, string, string) error {
	return f.leaseErr
}
func (f *indexManagementExecutionFixture) ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error {
	f.pinnedCalls++
	return errors.New("pinned execution attribution denied")
}

func TestIndexManagementAuthorityDoesNotRequireBusinessEndpoint(t *testing.T) {
	for _, mode := range []string{"management", "business", "foreign-target", "revoked", "old-epoch", "lease-denied", "unknown-action"} {
		t.Run(mode, func(t *testing.T) {
			scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "indexer", AgentInstanceID: "install", InstallationID: "install", AgentVersionID: "v1", PrincipalType: "user", PrincipalID: "manager", SessionID: "s", RunID: "index-root", AuthorizationEpoch: 1, TraceID: "trace"}
			ex := &indexManagementExecutionFixture{delegatedExecutionFixture: delegatedExecutionFixture{action: "policy.manage"}}
			id := capabilitySnapshotFixture{}
			target := catalog.EvaluationAgentTarget{AgentID: scope.AgentID, InstallationID: scope.InstallationID, AgentVersionID: scope.AgentVersionID}
			switch mode {
			case "business":
				ex.action = "run"
			case "foreign-target":
				target.InstallationID = "foreign"
			case "revoked":
				id.failure = errors.New("revoked")
			case "old-epoch":
				scope.AuthorizationEpoch = 2
			case "lease-denied":
				ex.leaseErr = errors.New("execution lease proof denied")
			case "unknown-action":
				ex.action = "untrusted"
			}
			a := capabilityExecutionAuthority{execution: ex, identity: id, catalog: delegatedCatalogFixture{target: target}}
			err := a.AuthorizeCapability(context.Background(), scope, "invoke", "body", "policy")
			if (err == nil) != (mode == "management") {
				t.Fatalf("management admission %s: %v", mode, err)
			}
			if mode == "business" && ex.pinnedCalls != 1 {
				t.Fatal("business endpoint check skipped")
			}
			if mode == "management" && ex.pinnedCalls != 0 {
				t.Fatal("indexing was routed through business endpoint")
			}
		})
	}
}
