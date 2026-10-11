package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

func TestPermissionInstallationTargetsUseIndependentLiveAuthority(t *testing.T) {
	scope := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	actor := catalog.ControlActor{PrincipalType: "user", PrincipalID: p.ID, TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	target := catalog.ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	for _, permission := range []string{"machine.manage", "authorization.change", "delegation.manage", "catalog.manage"} {
		t.Run(permission, func(t *testing.T) {
			snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p,
				Roles:       []identity.RoleDefinition{{Code: "specialist", Version: 1, ScopeTypes: []string{"application"}, Actions: []string{permission}, Assignable: true}},
				Memberships: []identity.Membership{{ID: "m", SubjectID: p.ID, Scope: scope, Status: "active"}},
				Bindings:    []identity.RoleBinding{{ID: "b", SubjectID: p.ID, Scope: scope, RoleCode: "specialist", RoleVersion: 1, Status: "active"}},
			}
			store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: snapshot}
			for action, required := range map[catalog.ControlAction]string{catalog.ControlAuthorizationTargets: "authorization.change", catalog.ControlWorkloadTargets: "machine.manage", catalog.ControlDelegationTargets: "delegation.manage", catalog.ControlRead: "catalog.manage"} {
				err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, action, target)
				if (err == nil) != (permission == required) {
					t.Fatalf("%s: %v", action, err)
				}
				for _, other := range []catalog.ControlScope{{}, {TenantID: "t"}, {TenantID: "t", DepartmentID: "d", ApplicationID: "other"}, {TenantID: "other", DepartmentID: "d", ApplicationID: "a"}} {
					if err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, action, other); !errors.Is(err, catalog.ErrCatalogForbidden) {
						t.Fatalf("scope escape %s: %v", action, err)
					}
				}
			}
			expired := time.Now().Add(-time.Second)
			store.snapshot.Bindings[0].Validity.ExpiresAt = &expired
			for _, action := range []catalog.ControlAction{catalog.ControlAuthorizationTargets, catalog.ControlWorkloadTargets, catalog.ControlDelegationTargets} {
				if err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, action, target); !errors.Is(err, catalog.ErrCatalogForbidden) {
					t.Fatal("expired authority survived", err)
				}
				store.policyError = errors.New("database unavailable")
				if err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, action, target); !errors.Is(err, store.policyError) {
					t.Fatal("outage fell back", err)
				}
				store.policyError = nil
			}
		})
	}
	for _, action := range []catalog.ControlAction{catalog.ControlAuthorizationTargets, catalog.ControlWorkloadTargets, catalog.ControlDelegationTargets} {
		if err := (identityCatalogControl{store: catalogIdentityStoreStub{principal: p}}).AuthorizeCatalogControl(context.Background(), actor, action, target); !errors.Is(err, catalog.ErrCatalogForbidden) {
			t.Fatal("legacy administrator gained new metadata view", err)
		}
	}
}
