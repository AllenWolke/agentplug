package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sharedkernel"
	"testing"
)

func TestSQLCapabilityResourceRequestApprovalAndRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	c := permissionApplicationCommand(f, "capability-request")
	c.Items = c.Items[:1]
	for _, tc := range []struct{ typ, action string }{{"model", "model.generate"}, {"tool", "tool.invoke"}, {"knowledge", "knowledge.search"}, {"memory", "memory.read"}} {
		c.Items = append(c.Items, PermissionRequestItem{ID: tc.typ, Kind: "resource", Scope: c.Scope, ResourceType: tc.typ, ResourceID: tc.typ + "-fixture", InstallationID: "fixture-installation", Action: tc.action, DataScope: DataScope{Type: "owner"}})
	}
	r, err := f.store.CreatePermissionRequest(f.ctx, f.actors[2], c)
	if err != nil {
		t.Fatal(err)
	}
	decision := applicationDecision(f, r, "capability-approve")
	decision.ApprovedItemIDs = []string{"operator", "model", "tool", "knowledge", "memory"}
	decision = previewApplicationDecision(t, f, decision)
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil || len(snapshot.Grants) != 0 {
		t.Fatal("preview wrote grants", snapshot, err)
	}
	failure := errors.New("capability source unavailable")
	f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{failure: failure})
	if _, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision); !errors.Is(err, failure) {
		t.Fatal("unavailable provider committed", err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil || snapshot.Principal.Revision != 1 || len(snapshot.Grants) != 0 {
		t.Fatal("failed decision advanced facts", snapshot, err)
	}
	f.store.SetCapabilityResourceResolver(capabilityFixtureResolver{})
	receipt, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], decision)
	if err != nil || retry.Authorization.ID != receipt.Authorization.ID {
		t.Fatal("retry not idempotent", retry, err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil || len(snapshot.Grants) != 4 {
		t.Fatal(snapshot, err)
	}
	for _, g := range snapshot.Grants {
		if g.ResourceID != g.ResourceType+"-fixture" || g.AgentInstanceID != "fixture-installation" {
			t.Fatal("approval lost typed resource", g)
		}
		scope := grantAuthorizationScope(g)
		q := PermissionQuery{Action: g.Action, Scope: scope, ResourceType: g.ResourceType, ResourceID: g.ResourceID, Now: f.now}
		got, err := EvaluatePermission(snapshot, q)
		if err != nil || !got.Allowed {
			t.Fatal(g, got, err)
		}
		q.Scope.ResourceID = "other-installation"
		got, err = EvaluatePermission(snapshot, q)
		if err != nil || got.Allowed {
			t.Fatal("grant crossed installation", g, got, err)
		}
	}
	revoke := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: r.SubjectID, ExpectedRevision: snapshot.Principal.Revision, IdempotencyKey: "capability-revoke", Reason: "revoke approved capabilities"}
	for _, g := range snapshot.Grants {
		revoke.RevokeGrantIDs = append(revoke.RevokeGrantIDs, g.ID)
	}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], revoke)
	if err != nil {
		t.Fatal(err)
	}
	revoke.PlanDigest, revoke.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], revoke); err != nil {
		t.Fatal(err)
	}
	current, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, r.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range snapshot.Grants {
		got, err := EvaluatePermission(current, PermissionQuery{Action: g.Action, Scope: grantAuthorizationScope(g), ResourceType: g.ResourceType, ResourceID: g.ResourceID, Now: f.now})
		if err != nil || got.Allowed {
			t.Fatal("revoked capability remains available", g, got, err)
		}
	}
}
