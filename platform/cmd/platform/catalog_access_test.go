package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

type catalogIdentityStoreStub struct {
	identity.Store
	principal identity.Principal
	err       error
}

func (s catalogIdentityStoreStub) GetPrincipal(context.Context, identity.PrincipalType, string) (identity.Principal, error) {
	return s.principal, s.err
}

func TestIdentityCatalogControlUsesStoredRolesAndExactScope(t *testing.T) {
	actor := catalog.ControlActor{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	appScope := catalog.ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"}
	globalScope := catalog.ControlScope{}
	tests := []struct {
		name      string
		principal identity.Principal
		target    catalog.ControlScope
		wantErr   bool
	}{
		{"platform admin global", identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, globalScope, false},
		{"platform admin own tenant", identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, appScope, false},
		{"platform admin tenant installation listing", identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-a"}, false},
		{"app admin cannot list tenant installations", identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-a"}, true},
		{"platform admin cannot cross tenant", identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-b", DepartmentID: "dept-b", ApplicationID: "app-b"}, true},
		{"department admin same department", identity.Principal{TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-b"}, false},
		{"department admin cannot cross department", identity.Principal{TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-a", DepartmentID: "dept-b", ApplicationID: "app-b"}, true},
		{"application admin exact app", identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, appScope, false},
		{"application admin cannot cross app", identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, catalog.ControlScope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-b"}, true},
		{"inactive principal", identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: false}, globalScope, true},
		{"ordinary user", identity.Principal{TenantID: "tenant-a", Roles: []string{"reviewer"}, IsActive: true}, appScope, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := identityCatalogControl{store: catalogIdentityStoreStub{principal: tt.principal}}
			err := authorizer.AuthorizeCatalogControl(context.Background(), actor, catalog.ControlManage, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AuthorizeCatalogControl error=%v wantErr=%t", err, tt.wantErr)
			}
		})
	}
}

func TestIdentityCatalogDeploymentControlRequiresPlatformRole(t *testing.T) {
	actor := catalog.ControlActor{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	target := catalog.ControlScope{TenantID: "tenant-a", DepartmentID: "dept-b", ApplicationID: "app-b"}
	for _, tt := range []struct {
		name      string
		principal identity.Principal
		wantErr   bool
	}{
		{name: "platform admin may deploy within tenant", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}},
		{name: "system admin may deploy", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"system_admin"}, IsActive: true}},
		{name: "department admin cannot deploy", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true}, wantErr: true},
		{name: "application admin cannot deploy", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := identityCatalogControl{store: catalogIdentityStoreStub{principal: tt.principal}}
			err := authorizer.AuthorizeCatalogControl(context.Background(), actor, catalog.ControlDeploy, target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AuthorizeCatalogControl deploy error=%v wantErr=%t", err, tt.wantErr)
			}
		})
	}
}

func TestIdentityCatalogControlDoesNotTrustBrowserIdentityOrRoles(t *testing.T) {
	actor := catalog.ControlActor{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	target := catalog.ControlScope{}
	for _, tt := range []struct {
		name      string
		actor     catalog.ControlActor
		principal identity.Principal
		storeErr  error
	}{
		{name: "wrong subject type", actor: catalog.ControlActor{TenantID: "tenant-a", PrincipalType: "service_principal", PrincipalID: "alice"}, principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}},
		{name: "tenant mismatch", actor: actor, principal: identity.Principal{TenantID: "tenant-b", Roles: []string{"platform_admin"}, IsActive: true}},
		{name: "identity unavailable", actor: actor, storeErr: errors.New("database unavailable")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := identityCatalogControl{store: catalogIdentityStoreStub{principal: tt.principal, err: tt.storeErr}}
			err := authorizer.AuthorizeCatalogControl(context.Background(), tt.actor, catalog.ControlManage, target)
			if err == nil {
				t.Fatal("authorization unexpectedly succeeded")
			}
			if tt.storeErr != nil && errors.Is(err, catalog.ErrCatalogForbidden) {
				t.Fatalf("store outage must not be disguised as a role denial: %v", err)
			}
		})
	}
}
