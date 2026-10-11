package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgovernance"
)

func TestIdentityModelGovernanceControlUsesStoredRoles(t *testing.T) {
	actor := modelgovernance.Actor{TenantID: "tenant-a", PrincipalType: "user", PrincipalID: "alice"}
	for _, tt := range []struct {
		name      string
		principal identity.Principal
		actor     modelgovernance.Actor
		target    modelgovernance.Scope
		storeErr  error
		wantErr   bool
	}{
		{name: "platform administrator", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, actor: actor},
		{name: "system administrator", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"system_admin"}, IsActive: true}, actor: actor},
		{name: "application administrator", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, actor: actor, wantErr: true},
		{name: "inactive administrator", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}}, actor: actor, wantErr: true},
		{name: "cross tenant", principal: identity.Principal{TenantID: "tenant-b", Roles: []string{"platform_admin"}, IsActive: true}, actor: actor, wantErr: true},
		{name: "non global target", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, actor: actor, target: modelgovernance.Scope{TenantID: "tenant-b"}, wantErr: true},
		{name: "service identity", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, actor: modelgovernance.Actor{TenantID: "tenant-a", PrincipalType: "service_principal", PrincipalID: "svc"}, wantErr: true},
		{name: "identity unavailable", actor: actor, storeErr: errors.New("database unavailable"), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			adapter := identityModelGovernanceControl{store: catalogIdentityStoreStub{principal: tt.principal, err: tt.storeErr}}
			err := adapter.AuthorizeModelGovernance(context.Background(), tt.actor, modelgovernance.ActionCreate, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("authorize error=%v wantErr=%t", err, tt.wantErr)
			}
			if tt.storeErr != nil && !errors.Is(err, tt.storeErr) {
				t.Fatalf("identity outage must propagate, got %v", err)
			}
		})
	}
}

func TestVersionedTenantModelOperationsRemainScopedWithoutGlobalPrivileges(t *testing.T) {
	p := identity.Principal{Type: identity.PrincipalUser, ID: "ops", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: p.ID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "b", SubjectID: p.ID, RoleCode: "platform_ops_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "tenant", TenantID: "t"}, Status: "active"}}}
	store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: snapshot}
	actor := modelgovernance.Actor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: p.ID, Browser: true}
	for _, action := range []modelgovernance.Action{modelgovernance.ActionManageDeployment, modelgovernance.ActionManagePolicy} {
		if err := (identityModelGovernanceControl{store: store}).AuthorizeModelGovernance(context.Background(), actor, action, modelgovernance.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}); err != nil {
			t.Fatal("tenant model operations rejected own application", action, err)
		}
	}
	for _, target := range []modelgovernance.Scope{{}, {TenantID: "other", DepartmentID: "d", ApplicationID: "a"}} {
		if err := (identityModelGovernanceControl{store: store}).AuthorizeModelGovernance(context.Background(), actor, modelgovernance.ActionRead, target); !errors.Is(err, modelgovernance.ErrForbidden) {
			t.Fatal("tenant role or old admin array obtained global/foreign authority", err)
		}
	}
	store.snapshot.Bindings[0].Status = "revoked"
	if err := (identityModelGovernanceControl{store: store}).AuthorizeModelGovernance(context.Background(), actor, modelgovernance.ActionManageDeployment, modelgovernance.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}); !errors.Is(err, modelgovernance.ErrForbidden) {
		t.Fatal("revoked role fell back to old admin array", err)
	}
	store.policyError = errors.New("IAM unavailable")
	if err := (identityModelGovernanceControl{store: store}).AuthorizeModelGovernance(context.Background(), actor, modelgovernance.ActionManagePolicy, modelgovernance.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}); !errors.Is(err, store.policyError) {
		t.Fatal("IAM outage did not fail closed", err)
	}
}
