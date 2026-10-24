package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"testing"
)

type capabilitySnapshotFixture struct {
	snapshot           identity.PermissionSnapshot
	failure            error
	executor           *identity.PermissionSnapshot
	binding            *identity.WorkloadBinding
	credentialDisabled bool
	credentialSecret   string
	snapshotReads      *int
	bindingReads       *int
	credentialReads    *int
}

func (f capabilitySnapshotFixture) CurrentAuthorizationEpoch(context.Context, sharedkernel.Scope, string) (uint64, error) {
	return 1, f.failure
}
func (f capabilitySnapshotFixture) PermissionSnapshot(_ context.Context, kind identity.PrincipalType, _ string) (identity.PermissionSnapshot, error) {
	if f.snapshotReads != nil {
		*f.snapshotReads++
	}
	if kind == identity.PrincipalServicePrincipal {
		if f.executor == nil {
			return identity.PermissionSnapshot{}, identity.ErrPermissionDenied
		}
		return *f.executor, f.failure
	}
	return f.snapshot, f.failure
}
func (f capabilitySnapshotFixture) GetMachineCredential(_ context.Context, tenant, subject string) (identity.MachineCredential, error) {
	if f.credentialReads != nil {
		*f.credentialReads++
	}
	status := "active"
	if f.credentialDisabled {
		status = "disabled"
	}
	secret := f.credentialSecret
	if secret == "" {
		secret = "workload-fixture-secret-value-12345678"
	}
	hash := sha256.Sum256([]byte(secret))
	return identity.MachineCredential{TenantID: tenant, PrincipalID: subject, Status: status, Revision: 1, SecretHash: hex.EncodeToString(hash[:]), NetworkCIDRs: []string{"127.0.0.1/32"}}, f.failure
}
func (f capabilitySnapshotFixture) ResolveWorkloadIdentity(context.Context, sharedkernel.Scope) (identity.WorkloadBinding, error) {
	if f.bindingReads != nil {
		*f.bindingReads++
	}
	if f.binding == nil {
		return identity.WorkloadBinding{}, identity.ErrPermissionDenied
	}
	return *f.binding, f.failure
}

func TestCapabilityIAMRequiresIndependentResourceGrant(t *testing.T) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	s := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "u", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: "u", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "b", SubjectID: "u", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "u", PrincipalType: "user", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v"}
	access := capability.CapabilityResourceAccess{Action: "knowledge.search", ResourceType: "knowledge", ResourceID: "kb"}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Grants: []identity.Grant{{ID: "machine-grant", SubjectType: identity.PrincipalServicePrincipal, SubjectID: "executor", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}}}
	binding := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	check := func(snapshot identity.PermissionSnapshot) error {
		return (capabilityExecutionAuthority{identity: capabilitySnapshotFixture{snapshot: snapshot, executor: &executor, binding: &binding}}).AuthorizeCapabilityResource(context.Background(), scope, access)
	}
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("role alone granted knowledge")
	}
	g := identity.Grant{ID: "g", SubjectType: identity.PrincipalUser, SubjectID: "u", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "i", ResourceType: "knowledge", ResourceID: "kb", Action: "knowledge.search", Status: "active", Effect: "allow", DataScope: identity.DataScope{Type: "owner"}}
	s.Grants = []identity.Grant{g}
	if err := check(s); err != nil {
		t.Fatal(err)
	}
	if err := (capabilityExecutionAuthority{identity: capabilitySnapshotFixture{snapshot: s, executor: &executor, binding: &binding, credentialDisabled: true}}).AuthorizeCapabilityResource(context.Background(), scope, access); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatal("disabled workload credential admitted", err)
	}
	saved := executor.Grants
	executor.Grants = nil
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("caller grant replaces executor grant")
	}
	executor.Grants = saved
	executor.Principal.IsActive = false
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("disabled executor admitted")
	}
	executor.Principal.IsActive = true
	binding.AgentVersionID = "other-version"
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("execution identity crossed version")
	}
	binding.AgentVersionID = "v"
	binding.Status = "revoked"
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("revoked execution binding admitted")
	}
	binding.Status = "active"
	s.Grants[0].AgentInstanceID = "other"
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("grant crossed installation")
	}
	s.Grants[0] = g
	deny := g
	deny.ID = "deny"
	deny.Effect = "deny"
	deny.DataScope = identity.DataScope{Type: "approved_organization"}
	s.Grants = append(s.Grants, deny)
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("deny ignored")
	}
	s.Mode = "unknown"
	if !errors.Is(check(s), identity.ErrPermissionDenied) {
		t.Fatal("unknown mode admitted")
	}
	failure := errors.New("SQL unavailable")
	if err := (capabilityExecutionAuthority{identity: capabilitySnapshotFixture{failure: failure}}).AuthorizeCapabilityResource(context.Background(), scope, access); !errors.Is(err, failure) {
		t.Fatal("SQL failure bypassed", err)
	}
}

func TestWorkloadAuthenticationRequiresBoundSecretAndPeer(t *testing.T) {
	scope := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentInstanceID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "u", PrincipalType: "user", SessionID: "s", RunID: "r", AuthorizationEpoch: 1, TraceID: "trace"}
	b := identity.WorkloadBinding{TenantID: "t", DepartmentID: "d", ApplicationID: "a", InstallationID: "i", AgentID: "agent", AgentVersionID: "v", PrincipalID: "executor", Status: "active", Revision: 1}
	executor := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalServicePrincipal, ID: "executor", TenantID: "t", IsActive: true}}
	f := capabilitySnapshotFixture{snapshot: identity.PermissionSnapshot{Mode: "v2"}, executor: &executor, binding: &b}
	secret := "workload-fixture-secret-value-12345678"
	auth := func(id, value, peer string) error {
		return (capabilityExecutionAuthority{identity: f}).AuthenticateWorkload(context.Background(), scope, id, value, peer)
	}
	if err := auth("executor", secret, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, secret, peer string }{{"", "", "127.0.0.1:1234"}, {"other", secret, "127.0.0.1:1234"}, {"executor", "incorrect-secret-with-long-enough-value", "127.0.0.1:1234"}, {"executor", secret, "192.0.2.1:1234"}} {
		if err := auth(tc.id, tc.secret, tc.peer); err == nil {
			t.Fatal("unauthenticated executor admitted")
		}
	}
	f.credentialSecret = "rotated-workload-fixture-secret-12345678"
	if err := auth("executor", secret, "127.0.0.1:1234"); err == nil {
		t.Fatal("old rotated credential admitted")
	}
	if err := auth("executor", f.credentialSecret, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	f.credentialDisabled = true
	if err := auth("executor", f.credentialSecret, "127.0.0.1:1234"); err == nil {
		t.Fatal("disabled credential admitted")
	}
}
