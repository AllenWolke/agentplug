package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/identity"
)

func TestConversationDeletionPlanUsesReviewerGrantAndLiveObjectChecks(t *testing.T) {
	ctx := context.Background()
	scope := conversation.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "reviewer"}
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "reviewer", TenantID: "t", IsActive: true}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "reviewer", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "role", SubjectID: "reviewer", RoleCode: "reviewer", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{{ID: "review", SubjectType: identity.PrincipalUser, SubjectID: "reviewer", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "install", ResourceType: "agent_installation", ResourceID: "install", Action: "business.review", Effect: "allow", Status: "active", DataScope: identity.DataScope{Type: "approved_organization"}}}}
	store := versionedCatalogStore{snapshot: snapshot}
	adapter := identityConversationAccess{store: store}
	plan, err := adapter.DeletionReadPlan(ctx, scope)
	if err != nil || plan.Legacy || len(plan.Allow) != 1 {
		t.Fatal("reviewer data plan rejected", plan, err)
	}
	resource := conversation.SessionResource{ID: "session", OwnerID: "owner", PrincipalType: "user", InstallationID: "install", AgentID: "agent", AgentVersionID: "v1"}
	if err := adapter.Authorize(ctx, scope, resource, "business.review"); err != nil {
		t.Fatal(err)
	}
	resource.OwnerID = scope.PrincipalID
	if err := adapter.Authorize(ctx, scope, resource, "business.review"); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("self review accepted", err)
	}
	store.snapshot.Grants = nil
	adapter = identityConversationAccess{store: store}
	plan, err = adapter.DeletionReadPlan(ctx, scope)
	if err != nil || len(plan.Allow) != 0 {
		t.Fatal("review role expanded without grant", plan, err)
	}
}

func TestConversationReadIsIndependentFromRunAndLegacyAdministrator(t *testing.T) {
	ctx := context.Background()
	scope := conversation.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "alice", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "binding", SubjectID: "alice", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}
	store := versionedCatalogStore{snapshot: snapshot}
	resource := conversation.SessionResource{ID: "session", OwnerID: "alice", PrincipalType: "user", InstallationID: "install", AgentID: "agent", AgentVersionID: "v1"}
	if err := (identityConversationAccess{store: store}).Authorize(ctx, scope, resource, "history.read"); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("legacy admin read without grant", err)
	}
	grant := identity.Grant{ID: "read", SubjectType: identity.PrincipalUser, SubjectID: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "install", ResourceType: "agent_installation", ResourceID: "install", Action: "history.read", Effect: "allow", Status: "active", DataScope: identity.DataScope{Type: "owner"}}
	store.snapshot.Grants = []identity.Grant{grant}
	adapter := identityConversationAccess{store: store}
	if err := adapter.Authorize(ctx, scope, resource, "history.read"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"run", "history.continue", "history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request"} {
		if err := adapter.Authorize(ctx, scope, resource, action); !errors.Is(err, conversation.ErrForbidden) {
			t.Fatal("read grant expanded action", action, err)
		}
	}
	projection, err := adapter.Project(ctx, scope, []conversation.Summary{{ID: "session", OwnerID: "alice", InstallationID: "install", CanContinue: true}})
	if err != nil || projection[0].CanContinue || !projection[0].Permissions["history.read"] || projection[0].Permissions["history.export"] {
		t.Fatal("incorrect read-only projection", projection, err)
	}
	foreign := resource
	foreign.OwnerID = "other"
	if err := adapter.Authorize(ctx, scope, foreign, "history.read"); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("owner scope crossed owner", err)
	}
	store.snapshot.Grants[0].DataScope = identity.DataScope{Type: "explicit_set", IDs: []string{"session"}}
	if err := (identityConversationAccess{store: store}).Authorize(ctx, scope, foreign, "history.read"); err != nil {
		t.Fatal("explicit session denied", err)
	}
	store.snapshot.Grants = append(store.snapshot.Grants, store.snapshot.Grants[0])
	store.snapshot.Grants[1].ID = "deny"
	store.snapshot.Grants[1].Effect = "deny"
	if err := (identityConversationAccess{store: store}).Authorize(ctx, scope, foreign, "history.read"); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("deny did not dominate", err)
	}
	store.snapshot.Grants = store.snapshot.Grants[:1]
	expired := time.Now().Add(-time.Second)
	store.snapshot.Grants[0].ExpiresAt = &expired
	if err := (identityConversationAccess{store: store}).Authorize(ctx, scope, resource, "history.read"); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("expired grant read", err)
	}
	store.policyError = errors.New("database unavailable")
	if err := (identityConversationAccess{store: store}).Authorize(ctx, scope, resource, "history.read"); !errors.Is(err, store.policyError) {
		t.Fatal("outage fallback", err)
	}
	store.policyError = nil
	store.snapshot.Mode = "unknown"
	if _, err := (identityConversationAccess{store: store}).ReadPlan(ctx, scope); !errors.Is(err, conversation.ErrForbidden) {
		t.Fatal("unknown mode fallback", err)
	}
}
