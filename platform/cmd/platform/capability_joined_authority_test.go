package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type joinedSnapshotFixture struct {
	capabilitySnapshotFixture
	joined, reads int
	inside        bool
}

type mutableEpochJoinedFixture struct {
	*joinedSnapshotFixture
	epoch uint64
}

func (f *mutableEpochJoinedFixture) CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error) {
	return f.epoch, nil
}

func (f *mutableEpochJoinedFixture) WithCurrentAuthorizationSnapshotContext(ctx context.Context, _ sharedkernel.Scope, _ string,
	check func(context.Context, uint64, identity.PermissionSnapshot) error) error {
	f.joinedSnapshotFixture.joined++
	f.joinedSnapshotFixture.inside = true
	defer func() { f.joinedSnapshotFixture.inside = false }()
	return check(ctx, f.epoch, f.snapshot)
}

func (f *joinedSnapshotFixture) WithCurrentAuthorizationSnapshot(_ context.Context, _ sharedkernel.Scope, _ string, check func(uint64, identity.PermissionSnapshot) error) error {
	f.joined++
	f.inside = true
	defer func() { f.inside = false }()
	return check(1, f.snapshot)
}

func (f *joinedSnapshotFixture) WithCurrentAuthorizationSnapshotContext(ctx context.Context, _ sharedkernel.Scope, _ string,
	check func(context.Context, uint64, identity.PermissionSnapshot) error) error {
	f.joined++
	f.inside = true
	defer func() { f.inside = false }()
	return check(ctx, 1, f.snapshot)
}

func (f *joinedSnapshotFixture) PermissionSnapshot(ctx context.Context, kind identity.PrincipalType, id string) (identity.PermissionSnapshot, error) {
	if kind != identity.PrincipalServicePrincipal {
		return identity.PermissionSnapshot{}, errors.New("caller snapshot reread on response fence")
	}
	f.reads++
	return f.capabilitySnapshotFixture.PermissionSnapshot(ctx, kind, id)
}

func TestJoinedCapabilityAuthorityReusesOneCallerReadButRechecksEveryFence(t *testing.T) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "s", RunID: "r", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "b", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}
	grant := identity.Grant{ID: "g", SubjectType: identity.PrincipalUser, SubjectID: "u", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	caller.Grants = []identity.Grant{grant}
	machineGrant := grant
	machineGrant.ID, machineGrant.SubjectType, machineGrant.SubjectID = "mg", identity.PrincipalServicePrincipal, "executor"
	machineGrant.DataScope = identity.DataScope{Type: "approved_organization"}
	machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{machineGrant}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	iam := &joinedSnapshotFixture{capabilitySnapshotFixture: capabilitySnapshotFixture{snapshot: caller, executor: &machine, binding: &binding}}
	execution := &stopOnlyAuthorityExecution{action: "run"}
	a := capabilityExecutionAuthority{identity: iam, execution: execution, catalog: stopOnlyAuthorityCatalog{expected: scope}}
	ctx := sharedkernel.WithExecutionLease(context.Background(), sharedkernel.ExecutionLeaseBinding{Revision: 7, TokenHash: strings.Repeat("a", 64)})
	check := func() (string, error) {
		return a.AuthorizeCapabilityAndResource(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64), capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: "kb"})
	}
	if _, err := check(); err != nil || iam.joined != 1 || iam.reads != 1 {
		t.Fatal("caller facts not shared within one fence", err, iam.joined, iam.reads)
	}
	iam.snapshot.Grants[0].Status = "revoked"
	if stage, err := check(); err == nil || stage != "RESOURCE_AUTHORITY" || iam.joined != 2 || iam.reads != 1 {
		t.Fatal("next fence reused revoked caller authority", stage, err, iam.joined, iam.reads)
	}
	iam.snapshot.Grants[0].Status = "active"
	machine.Grants = nil
	if stage, err := check(); err == nil || stage != "RESOURCE_AUTHORITY" || iam.joined != 3 || iam.reads != 2 {
		t.Fatal("independent executor authority was skipped", stage, err, iam.joined, iam.reads)
	}
	iam.snapshot.Principal.ID = "foreign"
	if _, err := check(); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("foreign caller snapshot was accepted", err)
	}
}

func TestResponseFenceReusesOnlySameEpochSnapshotsAndStillChecksLiveCommand(t *testing.T) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v", SessionID: "s", RunID: "r", AuthorizationEpoch: 1, TraceID: strings.Repeat("a", 32)}
	caller := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "b", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}
	caller.Grants = []identity.Grant{{ID: "g", SubjectType: identity.PrincipalUser, SubjectID: "u", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}}
	machineGrant := caller.Grants[0]
	machineGrant.ID, machineGrant.SubjectType, machineGrant.SubjectID = "mg", identity.PrincipalServicePrincipal, "executor"
	machineGrant.DataScope = identity.DataScope{Type: "approved_organization"}
	machine := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{machineGrant}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	baseIAM := &joinedSnapshotFixture{capabilitySnapshotFixture: capabilitySnapshotFixture{snapshot: caller, executor: &machine, binding: &binding}}
	iam := &mutableEpochJoinedFixture{joinedSnapshotFixture: baseIAM, epoch: 1}
	execution := &stopOnlyAuthorityExecution{action: "run"}
	authority := capabilityExecutionAuthority{identity: iam, execution: execution, catalog: stopOnlyAuthorityCatalog{expected: scope}}
	ctx := sharedkernel.WithExecutionLease(context.Background(), sharedkernel.ExecutionLeaseBinding{Revision: 7, TokenHash: strings.Repeat("a", 64)})
	access := capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: "kb"}
	if _, err := authority.AuthorizeCapabilityAndResource(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64), access); err != nil {
		t.Fatal("entry authorization failed", err)
	}
	if baseIAM.joined != 1 || baseIAM.reads != 1 {
		t.Fatal("entry snapshot must be read once under the joined IAM fence", baseIAM.joined, baseIAM.reads)
	}
	credential := identity.MachineCredential{TenantID: "t", PrincipalID: "executor", Status: "active", Revision: 1}
	facts := capability.NewCapabilityAdmissionFacts(scope, 1, caller, machine, binding, credential)
	if facts == nil {
		t.Fatal("verified entry facts were not constructed")
	}
	if err := authority.RecheckCapabilityAndResource(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64), access, facts); err != nil {
		t.Fatal("same-epoch live response fence failed", err)
	}
	if baseIAM.joined != 2 || baseIAM.reads != 2 {
		t.Fatal("response fence must refresh the caller snapshot under the epoch fence and refresh executor authority", baseIAM.joined, baseIAM.reads)
	}
	machine.Grants = nil
	if err := authority.RecheckCapabilityAndResource(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64), access, facts); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("revoked independent executor permission reused from caller epoch", err)
	}
	if baseIAM.reads != 3 {
		t.Fatal("executor permission was not freshly loaded on response fence", baseIAM.reads)
	}
	machine.Grants = []identity.Grant{machineGrant}
	iam.epoch = 2
	if err := authority.RecheckCapabilityAndResource(ctx, scope, "run", strings.Repeat("b", 64), strings.Repeat("c", 64), access, facts); err == nil {
		t.Fatal("changed IAM epoch reused stale permission snapshots")
	}
	if baseIAM.reads != 3 {
		t.Fatal("stale caller epoch should fail before reading executor snapshot", baseIAM.reads)
	}
}
