package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func businessReviewFixture() (versionedCatalogStore, sharedkernel.Scope) {
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "reviewer", TenantID: "t", IsActive: true, Roles: []string{"admin", "reviewer"}}
	store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: p.ID, Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "role", SubjectID: p.ID, RoleCode: "reviewer", RoleVersion: 1, Scope: app, Status: "active"}}, Grants: []identity.Grant{{ID: "grant", SubjectType: identity.PrincipalUser, SubjectID: p.ID, TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentInstanceID: "installation", ResourceType: "agent_installation", ResourceID: "installation", Action: "business.content.read", Effect: "allow", Status: "active", DataScope: identity.DataScope{Type: "explicit_set", IDs: []string{"qa-run"}}}}}}
	owner := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "initiator", AgentInstanceID: "installation", AgentID: "document-assistant", RunID: "qa-run"}
	return store, owner
}

func TestVersionedBusinessReviewNeedsRoleResourceAndCurrentDataScope(t *testing.T) {
	ctx := context.Background()
	for _, action := range []string{"business.content.read", "business.review"} {
		for _, tc := range []struct {
			name   string
			change func(*versionedCatalogStore, *sharedkernel.Scope)
		}{
			{"role revoked", func(s *versionedCatalogStore, _ *sharedkernel.Scope) { s.snapshot.Bindings = nil }},
			{"management role only", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				s.snapshot.Bindings[0].RoleCode = "super_admin"
				s.snapshot.Bindings[0].Scope = identity.ManagementScope{Type: "global"}
			}},
			{"member removed", func(s *versionedCatalogStore, _ *sharedkernel.Scope) { s.snapshot.Memberships = nil }},
			{"grant removed", func(s *versionedCatalogStore, _ *sharedkernel.Scope) { s.snapshot.Grants = nil }},
			{"other agent", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				s.snapshot.Grants[0].ResourceID = "other-installation"
			}},
			{"other app", func(_ *versionedCatalogStore, o *sharedkernel.Scope) { o.ApplicationID = "other" }},
			{"other object", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				s.snapshot.Grants[0].DataScope.IDs = []string{"other-run"}
			}},
			{"owner scope excludes reviewer", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				s.snapshot.Grants[0].DataScope = identity.DataScope{Type: "owner"}
			}},
			{"no authoritative assignment", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				s.snapshot.Grants[0].DataScope = identity.DataScope{Type: "assigned_task"}
			}},
			{"grant expired", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				expired := time.Now().Add(-time.Second)
				s.snapshot.Grants[0].ExpiresAt = &expired
			}},
			{"deny overrides", func(s *versionedCatalogStore, _ *sharedkernel.Scope) {
				g := s.snapshot.Grants[0]
				g.ID, g.Effect = "deny", "deny"
				s.snapshot.Grants = append(s.snapshot.Grants, g)
			}},
			{"unknown mode", func(s *versionedCatalogStore, _ *sharedkernel.Scope) { s.snapshot.Mode = "unknown" }},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				store, owner := businessReviewFixture()
				store.snapshot.Grants[0].Action = action
				if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", action); err != nil {
					t.Fatal("explicit positive boundary denied", err)
				}
				tc.change(&store, &owner)
				if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", action); !errors.Is(err, errBusinessReviewForbidden) {
					t.Fatal("legacy role bypassed current business boundary", err)
				}
			})
		}
	}
	store, owner := businessReviewFixture()
	if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", "business.review"); !errors.Is(err, errBusinessReviewForbidden) {
		t.Fatal("content grant also approved review", err)
	}
	owner.PrincipalID = "reviewer"
	if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", "business.content.read"); !errors.Is(err, errBusinessReviewForbidden) {
		t.Fatal("self reviewer accepted", err)
	}
	store, owner = businessReviewFixture()
	store.policyError = errors.New("IAM unavailable")
	if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", "business.content.read"); !errors.Is(err, store.policyError) {
		t.Fatal("IAM failure revived old admin role", err)
	}
	store.policyError = nil
	for _, mode := range []string{"legacy", "shadow"} {
		store.snapshot.Mode = mode
		if err := (identityBusinessReviewControl{store: store}).Authorize(ctx, owner, "reviewer", "business.review"); err != nil {
			t.Fatal("explicit legacy compatibility regressed", mode, err)
		}
	}
}
