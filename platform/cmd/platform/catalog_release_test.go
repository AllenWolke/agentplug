package main

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

func TestCatalogReleaseActionsDoNotFallBackToLegacyAdministrator(t *testing.T) {
	actor := catalog.ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	for _, granted := range []string{"catalog.manage", "release.submit", "release.approve"} {
		for _, scope := range []identity.ManagementScope{{Type: "global"}, {Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}} {
			snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p,
				Roles:       []identity.RoleDefinition{{Code: "specialist", Version: 1, ScopeTypes: []string{"global", "application"}, Actions: []string{granted}, Assignable: true}},
				Memberships: []identity.Membership{{ID: "m", SubjectID: p.ID, Scope: scope, Status: "active"}},
				Bindings:    []identity.RoleBinding{{ID: "b", SubjectID: p.ID, RoleCode: "specialist", RoleVersion: 1, Scope: scope, Status: "active"}},
			}
			adapter := identityCatalogControl{store: versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: snapshot}}
			for action, required := range map[catalog.ControlAction]string{catalog.ControlRead: "catalog.manage", catalog.ControlManage: "catalog.manage", catalog.ControlSubmit: "release.submit", catalog.ControlApprove: "release.approve"} {
				err := adapter.AuthorizeCatalogControl(context.Background(), actor, action, catalog.ControlScope{})
				want := scope.Type == "global" && required == granted
				if (err == nil) != want {
					t.Fatalf("grant=%s scope=%s action=%s allowed=%t error=%v", granted, scope.Type, action, want, err)
				}
			}
		}
	}
}
