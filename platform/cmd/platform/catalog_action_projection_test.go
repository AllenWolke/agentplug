package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

type countingCatalogSnapshot struct {
	versionedCatalogStore
	reads int
}

func (s *countingCatalogSnapshot) PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error) {
	s.reads++
	return s.snapshot, s.policyError
}

func TestCatalogActionProjectionSeparatesDiscoveryRunAndHistory(t *testing.T) {
	ctx := context.Background()
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	actor := catalog.ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	store := &countingCatalogSnapshot{versionedCatalogStore: versionedCatalogStore{snapshot: identity.PermissionSnapshot{Mode: "v2", Principal: identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "alice", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "operator", SubjectID: "alice", RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active"}}}}}
	adapter := identityCatalogAccess{store: store}
	check := func(discover, run, read bool) {
		t.Helper()
		before := store.reads
		result, err := adapter.ProjectAgentActions(ctx, actor, []string{"install", "foreign-install", "install"})
		if err != nil || store.reads != before+1 || len(result) != 2 || result["install"]["discover"] != discover || result["install"]["run"] != run || result["install"]["history.read"] != read {
			t.Fatalf("projection/snapshot mismatch: result=%v error=%v reads=%d", result, err, store.reads-before)
		}
		for action, allowed := range result["foreign-install"] {
			if allowed {
				t.Fatal("grant crossed installation", action)
			}
		}
	}
	check(false, false, false)
	grant := identity.Grant{ID: "discover", SubjectType: identity.PrincipalUser, SubjectID: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceType: "agent_installation", ResourceID: "install", AgentInstanceID: "install", Action: "discover", Effect: "allow", Status: "active", DataScope: identity.DataScope{Type: "owner"}}
	store.snapshot.Grants = []identity.Grant{grant}
	check(true, false, false)
	grant.ID, grant.Action = "run", "run"
	store.snapshot.Grants = append(store.snapshot.Grants, grant)
	check(true, true, false)
	grant.ID, grant.Action = "read", "history.read"
	store.snapshot.Grants = append(store.snapshot.Grants, grant)
	check(true, true, true)
	grant.ID, grant.Action, grant.Effect = "deny-run", "run", "deny"
	store.snapshot.Grants = append(store.snapshot.Grants, grant)
	check(true, false, true)
	store.snapshot.Grants[0].Status = "revoked"
	check(false, false, true)
	expired := time.Now().Add(-time.Second)
	store.snapshot.Grants[2].ExpiresAt = &expired
	check(false, false, false)
	store.policyError = errors.New("database unavailable")
	if _, err := adapter.ProjectAgentActions(ctx, actor, []string{"install"}); !errors.Is(err, store.policyError) {
		t.Fatal("SQL failure fell back to legacy admin", err)
	}
	store.policyError = nil
	store.snapshot.Mode = "unknown"
	if _, err := adapter.ProjectAgentActions(ctx, actor, []string{"install"}); !errors.Is(err, identity.ErrInvalidResource) {
		t.Fatal("unknown policy mode granted", err)
	}
	store.snapshot.Mode = "v2"
	actor.TenantID = "foreign"
	if _, err := adapter.ProjectAgentActions(ctx, actor, []string{"install"}); !errors.Is(err, catalog.ErrCatalogForbidden) {
		t.Fatal("caller crossed tenant", err)
	}
}

type legacyCatalogProjectionStore struct{ versionedCatalogStore }

func (s legacyCatalogProjectionStore) ListGrants(_ context.Context, tenant, department, application, installation string, typ identity.PrincipalType, subject, action string) ([]identity.Grant, error) {
	if action != "discover" {
		return nil, nil
	}
	return []identity.Grant{{ID: "legacy-discover", TenantID: tenant, DepartmentID: department, ApplicationID: application, AgentInstanceID: installation, SubjectType: typ, SubjectID: subject, Action: action, Status: "active", Effect: "allow", Revision: 1}}, nil
}

func TestCatalogActionProjectionPreservesExplicitLegacyDiscovery(t *testing.T) {
	principal := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true}
	store := legacyCatalogProjectionStore{versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: principal}, snapshot: identity.PermissionSnapshot{Mode: "legacy", Principal: principal}}}
	result, err := (identityCatalogAccess{store: store}).ProjectAgentActions(context.Background(), catalog.ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}, []string{"install"})
	if err != nil || !result["install"]["discover"] || result["install"]["run"] {
		t.Fatal("legacy grants changed", result, err)
	}
}
