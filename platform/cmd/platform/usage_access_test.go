package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestIdentityUsageControlRejectsInactiveCrossTenantAndOrdinaryUsers(t *testing.T) {
	actor := usagecost.Actor{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	scope := usagecost.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	for _, tt := range []struct {
		name      string
		principal identity.Principal
		scope     usagecost.Scope
		storeErr  error
		wantErr   bool
	}{
		{name: "application admin", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, scope: scope},
		{name: "ordinary user", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"user"}, IsActive: true}, scope: scope, wantErr: true},
		{name: "inactive admin", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}}, scope: scope, wantErr: true},
		{name: "different tenant", principal: identity.Principal{TenantID: "tenant-b", Roles: []string{"platform_admin"}, IsActive: true}, scope: scope, wantErr: true},
		{name: "scope override", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, scope: usagecost.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-b"}, wantErr: true},
		{name: "identity outage", scope: scope, storeErr: errors.New("database unavailable"), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := identityUsageControl{store: catalogIdentityStoreStub{principal: tt.principal, err: tt.storeErr}}
			err := authorizer.AuthorizeUsageCost(context.Background(), actor, usagecost.ActionReadUsage, tt.scope)
			if (err != nil) != tt.wantErr {
				t.Fatalf("authorize error=%v wantErr=%t", err, tt.wantErr)
			}
			if tt.storeErr != nil && !errors.Is(err, tt.storeErr) {
				t.Fatalf("identity outage must propagate: %v", err)
			}
		})
	}
}

func TestLedgerBudgetRequiresVersionedModelConfigureAndNoLegacyFallback(t *testing.T) {
	actor := usagecost.Actor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	scope := usagecost.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentVersionID: "v1"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "m", SubjectID: p.ID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "b", SubjectID: p.ID, RoleCode: "application_admin", RoleVersion: 1, Scope: app, Status: "active"}}}
	store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: snapshot}
	if err := (identityUsageControl{store: store}).AuthorizeUsageCost(context.Background(), actor, usagecost.ActionManageLedgerBudget, scope); !errors.Is(err, usagecost.ErrUsageForbidden) {
		t.Fatal("legacy admin array bypassed v2 budget denial", err)
	}
	store.snapshot.Bindings[0].RoleCode = "platform_ops_admin"
	store.snapshot.Bindings[0].Scope = identity.ManagementScope{Type: "tenant", TenantID: "t"}
	if err := (identityUsageControl{store: store}).AuthorizeUsageCost(context.Background(), actor, usagecost.ActionManageLedgerBudget, scope); err != nil {
		t.Fatal("model-configure budget action rejected", err)
	}
	store.policyError = errors.New("IAM unavailable")
	if err := (identityUsageControl{store: store}).AuthorizeUsageCost(context.Background(), actor, usagecost.ActionManageLedgerBudget, scope); !errors.Is(err, store.policyError) {
		t.Fatal("budget IAM outage used legacy administrator role", err)
	}
}
