package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestVersionedAuditMetadataUsesScopedRoleWithoutLegacyFallback(t *testing.T) {
	ctx := context.Background()
	app := identity.ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	p := identity.Principal{Type: identity.PrincipalUser, ID: "alice", TenantID: "t", IsActive: true, Roles: []string{"admin", "auditor"}}
	store := versionedCatalogStore{catalogIdentityStoreStub: catalogIdentityStoreStub{principal: p}, snapshot: identity.PermissionSnapshot{Mode: "v2", Principal: p, Roles: identity.BuiltinRoleDefinitions(), Memberships: []identity.Membership{{ID: "member", SubjectID: "alice", Scope: app, Status: "active"}}, Bindings: []identity.RoleBinding{{ID: "auditor", SubjectID: "alice", RoleCode: "auditor", RoleVersion: 1, Scope: app, Status: "active"}}}}
	actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: "alice", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	target := audit.MetadataScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, target); err != nil {
		t.Fatal("scoped auditor denied without business grant", err)
	}
	for _, forbidden := range []audit.MetadataScope{{Type: "global"}, {Type: "tenant", TenantID: "t"}, {Type: "department", TenantID: "t", DepartmentID: "d"}, {Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "other"}, {Type: "application", TenantID: "foreign", DepartmentID: "d", ApplicationID: "a"}} {
		if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, forbidden); !errors.Is(err, audit.ErrMetadataForbidden) {
			t.Fatal("auditor escaped binding", forbidden, err)
		}
	}
	global := audit.MetadataScope{Type: "global"}
	store.snapshot.Bindings[0].Scope = identity.ManagementScope{Type: "global"}
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, global); err != nil {
		t.Fatal("explicit global audit binding denied", err)
	}
	expired := time.Now().Add(-time.Second)
	store.snapshot.Bindings[0].Validity.ExpiresAt = &expired
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, global); !errors.Is(err, audit.ErrMetadataForbidden) {
		t.Fatal("expired auditor survived", err)
	}
	store.snapshot.Bindings = nil
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, target); !errors.Is(err, audit.ErrMetadataForbidden) {
		t.Fatal("old role array revived revoked auditor", err)
	}
	store.policyError = errors.New("policy unavailable")
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, target); !errors.Is(err, store.policyError) {
		t.Fatal("policy outage fell back to legacy", err)
	}
	store.policyError = nil
	store.snapshot.Mode = "unknown"
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, target); err == nil {
		t.Fatal("unknown mode allowed audit")
	}
	store.snapshot.Mode = "legacy"
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, target); err != nil {
		t.Fatal("legacy current-workspace audit regressed", err)
	}
	if err := (identityAuditMetadataControl{store: store}).Authorize(ctx, actor, global); !errors.Is(err, audit.ErrMetadataForbidden) {
		t.Fatal("legacy role was broadened to global")
	}
}
