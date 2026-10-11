package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
)

type versionedCatalogStore struct {
	catalogIdentityStoreStub
	identity.PermissionRepository
	snapshot    identity.PermissionSnapshot
	policyError error
}

func (s versionedCatalogStore) PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error) {
	return s.snapshot, s.policyError
}
func (s versionedCatalogStore) ResolvePermission(_ context.Context, _ identity.PrincipalType, _ string, q identity.PermissionQuery) (identity.PermissionDecision, error) {
	q.Now = time.Now().UTC()
	return identity.EvaluatePermission(s.snapshot, q)
}

func TestVersionedControlCannotFallBackToLegacyAdministrator(t *testing.T) {
	scope := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin"}}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(),
		Memberships: []identity.Membership{{ID: "member", SubjectID: "alice", Scope: scope, Status: "active"}},
		Bindings:    []identity.RoleBinding{{ID: "binding", SubjectID: "alice", RoleCode: "application_admin", RoleVersion: 1, Scope: scope, Status: "active"}}}
	store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: snapshot}
	adapter := identityCatalogControl{store: store}
	actor := catalog.ControlActor{PrincipalType: "user", PrincipalID: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	if err := adapter.AuthorizeCatalogControl(context.Background(), actor, catalog.ControlRead, catalog.ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}); err != nil {
		t.Fatal("scoped role denied", err)
	}
	for _, target := range []catalog.ControlScope{{}, {TenantID: "t"}, {TenantID: "t", DepartmentID: "d", ApplicationID: "other"}, {TenantID: "t", DepartmentID: "other", ApplicationID: "a"}} {
		if err := adapter.AuthorizeCatalogControl(context.Background(), actor, catalog.ControlRead, target); !errors.Is(err, catalog.ErrCatalogForbidden) {
			t.Fatal("legacy admin escaped scoped v2 decision", target, err)
		}
	}
	expired := time.Now().Add(-time.Second)
	store.snapshot.Bindings[0].Validity.ExpiresAt = &expired
	if err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, catalog.ControlRead, catalog.ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}); !errors.Is(err, catalog.ErrCatalogForbidden) {
		t.Fatal("expired scoped role survived", err)
	}
	store.policyError = errors.New("policy database unavailable")
	if err := (identityCatalogControl{store: store}).AuthorizeCatalogControl(context.Background(), actor, catalog.ControlRead, catalog.ControlScope{}); !errors.Is(err, store.policyError) {
		t.Fatal("policy outage fell back to legacy role", err)
	}
	store.policyError = nil
	store.snapshot.Mode = "unrecognized"
	if handled, err := authorizeVersionedControl(context.Background(), store, "alice", "catalog.manage", "", "", ""); !handled || err == nil {
		t.Fatal("unknown mode fell back to legacy role")
	}
}

func TestRequestableCatalogRequiresCurrentMembershipWithoutBusinessGrant(t *testing.T) {
	scope := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true}
	snapshot := identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "alice", Scope: scope, Status: "active"}}}
	actor := catalog.ControlActor{PrincipalType: "user", PrincipalID: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	target := catalog.ControlScope{TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	for _, tc := range []struct {
		name   string
		change func(*versionedCatalogStore)
		want   bool
	}{
		{"member without role or grant", func(*versionedCatalogStore) {}, true},
		{"membership removed", func(s *versionedCatalogStore) { s.snapshot.Memberships = nil }, false},
		{"membership expired", func(s *versionedCatalogStore) {
			expired := time.Now().Add(-time.Second)
			s.snapshot.Memberships[0].Validity.ExpiresAt = &expired
		}, false},
		{"principal disabled", func(s *versionedCatalogStore) { s.principal.IsActive = false; s.snapshot.Principal.IsActive = false }, false},
		{"unknown policy mode", func(s *versionedCatalogStore) { s.snapshot.Mode = "unknown" }, false},
		{"policy unavailable", func(s *versionedCatalogStore) { s.policyError = errors.New("unavailable") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copySnapshot := snapshot
			copySnapshot.Memberships = append([]identity.Membership(nil), snapshot.Memberships...)
			s := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: copySnapshot}
			tc.change(&s)
			err := (identityCatalogControl{store: s}).AuthorizeCatalogControl(context.Background(), actor, catalog.ControlRequestable, target)
			if (err == nil) != tc.want {
				t.Fatalf("requestable metadata err=%v want allowed=%v", err, tc.want)
			}
			if tc.want {
				d, err := s.ResolvePermission(context.Background(), identity.PrincipalUser, "alice", identity.PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "i"})
				if err != nil || d.Allowed {
					t.Fatalf("metadata access acquired business rights: %+v %v", d, err)
				}
			}
		})
	}
}
