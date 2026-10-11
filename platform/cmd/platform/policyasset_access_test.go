package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
)

func TestIdentityPolicyAssetControlScopesRolesToTenantDepartmentAndApplication(t *testing.T) {
	actor := policyasset.Actor{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", PrincipalType: "user", PrincipalID: "alice"}
	target := policyasset.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "agent-a", AgentVersionID: "v1"}
	for _, tt := range []struct {
		name      string
		principal identity.Principal
		target    policyasset.Scope
		storeErr  error
		wantErr   bool
	}{
		{name: "application admin owns app", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, target: target},
		{name: "application admin cannot cross app", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"application_admin"}, IsActive: true}, target: policyasset.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-b", AgentID: "agent-a", AgentVersionID: "v1"}, wantErr: true},
		{name: "department admin owns department", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true}, target: target},
		{name: "department admin cannot cross department", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"department_admin"}, IsActive: true}, target: policyasset.Scope{TenantID: "tenant-a", DepartmentID: "dept-b", ApplicationID: "app-b", AgentID: "agent-a", AgentVersionID: "v1"}, wantErr: true},
		{name: "platform admin owns tenant", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, target: target},
		{name: "platform admin cannot cross tenant", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}, IsActive: true}, target: policyasset.Scope{TenantID: "tenant-b", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "agent-a", AgentVersionID: "v1"}, wantErr: true},
		{name: "inactive", principal: identity.Principal{TenantID: "tenant-a", Roles: []string{"platform_admin"}}, target: target, wantErr: true},
		{name: "identity failure", target: target, storeErr: errors.New("database unavailable"), wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			adapter := identityPolicyAssetControl{store: catalogIdentityStoreStub{principal: tt.principal, err: tt.storeErr}}
			err := adapter.AuthorizePolicyAsset(context.Background(), actor, policyasset.ActionPublish, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("authorize error=%v wantErr=%t", err, tt.wantErr)
			}
			if tt.storeErr != nil && !errors.Is(err, tt.storeErr) {
				t.Fatalf("identity failure must propagate: %v", err)
			}
		})
	}
}

func TestVersionedPolicyAssetActionsAreIndependentAndCannotFallBack(t *testing.T) {
	actor := policyasset.Actor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	target := policyasset.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentVersionID: "v1"}
	scope := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	principal := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	for _, granted := range []string{"prompt.manage", "tool.manage", "policy.manage"} {
		t.Run(granted, func(t *testing.T) {
			snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: principal,
				Roles:       []identity.RoleDefinition{{Code: "specialist", Version: 1, ScopeTypes: []string{"application"}, Actions: []string{granted}, Assignable: true}},
				Memberships: []identity.Membership{{ID: "m", SubjectID: "alice", Scope: scope, Status: "active"}},
				Bindings:    []identity.RoleBinding{{ID: "b", SubjectID: "alice", RoleCode: "specialist", RoleVersion: 1, Scope: scope, Status: "active"}},
			}
			adapter := identityPolicyAssetControl{store: versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: principal}, snapshot: snapshot}}
			catalogAdapter := identityCatalogControl{store: adapter.store}
			catalogActor := catalog.ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
			for action, required := range map[catalog.ControlAction]string{catalog.ControlPromptTargets: "prompt.manage", catalog.ControlToolTargets: "tool.manage", catalog.ControlPolicyTargets: "policy.manage", catalog.ControlRead: "catalog.manage"} {
				err := catalogAdapter.AuthorizeCatalogControl(context.Background(), catalogActor, action, catalog.ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"})
				if (err == nil) != (required == granted) {
					t.Fatalf("target enumeration grant %s action %s: %v", granted, action, err)
				}
			}
			for _, operation := range []policyasset.Action{policyasset.ActionRead, policyasset.ActionCreate, policyasset.ActionUpdate, policyasset.ActionPublish} {
				for typ, required := range map[policyasset.AssetType]string{policyasset.AssetPrompt: "prompt.manage", policyasset.AssetTool: "tool.manage", policyasset.AssetModel: "policy.manage", "": "policy.manage"} {
					err := adapter.AuthorizeTypedPolicyAsset(context.Background(), actor, operation, target, typ)
					if (err == nil) != (required == granted) {
						t.Fatalf("grant %s authorized type %s operation %s: %v", granted, typ, operation, err)
					}
				}
				if err := adapter.AuthorizePolicyAsset(context.Background(), actor, operation, target); (err == nil) != (granted == "policy.manage") {
					t.Fatal("snapshot authorization escaped component permissions", err)
				}
			}
			other := target
			other.ApplicationID = "other"
			if err := adapter.AuthorizeTypedPolicyAsset(context.Background(), actor, policyasset.ActionCreate, other, policyasset.AssetPrompt); err == nil {
				t.Fatal("cross-app write allowed")
			}
		})
	}
}
