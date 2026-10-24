package capability

import (
	"context"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestCapabilityAdmissionFactsAreRequestAndEpochBound(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u",
		PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent",
		AgentVersionID: "v", SessionID: "s", RunID: "run", AuthorizationEpoch: 3, TraceID: strings.Repeat("a", 32)}
	ctx := context.WithValue(context.Background(), capabilityFactsCaptureKey{}, &capabilityFactsCapture{})
	if !CaptureCapabilityAdmissionEpoch(ctx, 3) {
		t.Fatal("joined entry epoch was not captured")
	}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "u", Type: identity.PrincipalUser, TenantID: "t"}}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "machine", Type: identity.PrincipalServicePrincipal, TenantID: "t"}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i",
		AgentID: "agent", AgentVersionID: "v", PrincipalID: "machine", Status: "active", Revision: 1}
	credential := identity.MachineCredential{TenantID: "t", PrincipalID: "machine", Status: "active", Revision: 1}
	facts := NewCapabilityAdmissionFacts(scope, 3, caller, executor, binding, credential)
	if facts == nil || !CaptureCapabilityAdmissionFacts(ctx, facts) {
		t.Fatal("complete verified facts were not captured")
	}
	capture := ctx.Value(capabilityFactsCaptureKey{}).(*capabilityFactsCapture)
	if capture.forScope(scope) == nil {
		t.Fatal("exact request scope facts were not readable")
	}
	changedEpoch := scope
	changedEpoch.AuthorizationEpoch++
	if capture.forScope(changedEpoch) != nil {
		t.Fatal("stale-epoch facts escaped their request fence")
	}
	otherScope := scope
	otherScope.RunID = "other-run"
	if capture.forScope(otherScope) != nil || CaptureCapabilityAdmissionFacts(ctx, facts) {
		t.Fatal("facts were reused across runs or overwritten")
	}
}

func TestCapabilityAdmissionFactsFailClosedWhenIncomplete(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u",
		PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent",
		AgentVersionID: "v", SessionID: "s", RunID: "run", AuthorizationEpoch: 3, TraceID: strings.Repeat("a", 32)}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "u", Type: identity.PrincipalUser, TenantID: "t"}}
	if NewCapabilityAdmissionFacts(scope, 3, caller, identity.PermissionSnapshot{}, identity.WorkloadBinding{}, identity.MachineCredential{}) != nil {
		t.Fatal("incomplete workload facts were cached")
	}
}

func TestCapabilityAdmissionFactsDetachMutableSnapshotSlices(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u",
		PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent",
		AgentVersionID: "v", SessionID: "s", RunID: "run", AuthorizationEpoch: 3, TraceID: strings.Repeat("b", 32)}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "u", Type: identity.PrincipalUser,
		TenantID: "t", Roles: []string{"operator"}}, Grants: []identity.Grant{{DataScope: identity.DataScope{Type: "explicit_set", IDs: []string{"owned"}}}}}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{ID: "machine",
		Type: identity.PrincipalServicePrincipal, TenantID: "t"}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i",
		AgentID: "agent", AgentVersionID: "v", PrincipalID: "machine", Status: "active", Revision: 1,
		AllowedAgentVersionIDs: []string{"v"}}
	credential := identity.MachineCredential{TenantID: "t", PrincipalID: "machine", Status: "active", Revision: 1,
		NetworkCIDRs: []string{"127.0.0.1/32"}}
	facts := NewCapabilityAdmissionFacts(scope, 3, caller, executor, binding, credential)
	if facts == nil {
		t.Fatal("complete admission facts were rejected")
	}
	caller.Principal.Roles[0] = "revoked"
	caller.Grants[0].DataScope.IDs[0] = "foreign"
	binding.AllowedAgentVersionIDs[0] = "foreign"
	credential.NetworkCIDRs[0] = "0.0.0.0/0"
	_, _, storedCaller, _, storedBinding, storedCredential, ok := facts.SnapshotValues()
	if !ok || storedCaller.Principal.Roles[0] != "operator" || storedCaller.Grants[0].DataScope.IDs[0] != "owned" ||
		storedBinding.AllowedAgentVersionIDs[0] != "v" || storedCredential.NetworkCIDRs[0] != "127.0.0.1/32" {
		t.Fatal("caller-owned mutable slices changed the retained facts")
	}
	storedCaller.Principal.Roles[0] = "mutated-return"
	storedBinding.AllowedAgentVersionIDs[0] = "mutated-return"
	_, _, storedCaller, _, storedBinding, _, ok = facts.SnapshotValues()
	if !ok || storedCaller.Principal.Roles[0] != "operator" || storedBinding.AllowedAgentVersionIDs[0] != "v" {
		t.Fatal("returned mutable slices changed the retained facts")
	}
}
