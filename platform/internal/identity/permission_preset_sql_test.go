package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"reflect"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLPresetChangeRetainsOtherApplicationAndRejectsPartialDelegation(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	scope := f.command(2, "unused").Scope
	target := f.actors[2].PrincipalID
	other := scope
	other.ApplicationID += "-other"
	if err := f.store.CreateApplication(f.ctx, Application{ID: other.ApplicationID, TenantID: other.TenantID, DepartmentID: other.DepartmentID, Code: other.ApplicationID, Name: "other application", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	member := Membership{ID: target + "-other-member", SubjectID: target, Scope: other, Status: "active", Revision: 1}
	if err := persistMembershipMutation(f.ctx, tx, member, 0); err != nil {
		t.Fatal(err)
	}
	independent := RoleBinding{ID: target + "-other-role", SubjectID: target, RoleCode: "operator", RoleVersion: 1, Scope: other, Status: "active", Revision: 1, SourceID: "independent-application"}
	if err := insertRoleBinding(f.ctx, tx, independent); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	expires := f.now.Add(30 * time.Minute)
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target, ExpectedRevision: 1, IdempotencyKey: "preset-initial", Reason: "explicit installation and short identity", Preset: &PresetSelection{Code: "operator", Version: 1, Scope: scope, ResourceIDs: []string{"fixture-installation"}, Validity: Validity{ExpiresAt: &expires}}}
	preview := func(actor sharedkernel.Scope, c AuthorizationChangeCommand) AuthorizationChangeCommand {
		t.Helper()
		p, err := f.store.PreviewAuthorizationChange(f.ctx, actor, c)
		if err != nil {
			t.Fatal(err)
		}
		c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
		return c
	}
	change = preview(f.actors[0], change)
	fault := errors.New("preset audit unavailable")
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return fault })
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], change); !errors.Is(err, fault) {
		t.Fatal("preset audit failure ignored", err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, target)
	if err != nil || snapshot.Principal.Revision != 1 || len(snapshot.Bindings) != 1 || len(snapshot.Grants) != 0 {
		t.Fatal("preset partially persisted", snapshot, err)
	}
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	first, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], change)
	if err != nil || len(first.Change.Bindings) != 1 || len(first.Change.Grants) != 5 {
		t.Fatal("preset default expansion incomplete", first, err)
	}
	for _, g := range first.Change.Grants {
		if g.PresetCode != "operator" || g.PresetVersion != 1 || g.SourceID == "" || g.ExpiresAt == nil || !g.ExpiresAt.Equal(expires) || g.ResourceID != "fixture-installation" {
			t.Fatal("preset provenance or validity lost", g)
		}
	}
	// Replacing only the explicitly chosen application role preserves all other sources.
	replacement := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: target, ExpectedRevision: first.Revision, IdempotencyKey: "preset-replace", Reason: "selected application role replacement", Preset: &PresetSelection{Code: "reviewer", Version: 1, Scope: scope, ResourceIDs: []string{"fixture-installation"}}, RevokeBindingIDs: []string{first.Change.Bindings[0].ID}}
	for _, g := range first.Change.Grants {
		replacement.RevokeGrantIDs = append(replacement.RevokeGrantIDs, g.ID)
	}
	replacement = preview(f.actors[0], replacement)
	second, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], replacement)
	if err != nil || len(second.Change.Bindings) != 1 || len(second.Change.Grants) != 2 {
		t.Fatal("reviewer replacement failed", second, err)
	}
	snapshot, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, target)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range snapshot.Bindings {
		if b.ID == independent.ID {
			found = reflect.DeepEqual(b, independent)
		}
	}
	if !found {
		t.Fatal("replacement changed another application's role")
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: "run", Scope: scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("revoked operator business authorization survived", decision, err)
	}
	// Publishing another preset version cannot rewrite already expanded permissions.
	var definition IdentityPreset
	for _, p := range BuiltinIdentityPresets() {
		if p.Code == "reviewer" {
			definition = p
		}
	}
	definition.Version = 2
	definition.ResourceActions = append(definition.ResourceActions, "history.export")
	raw, _ := json.Marshal(definition)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_preset_definition(preset_code,preset_version,payload,content_hash) VALUES(?,?,?,?)`), definition.Code, definition.Version, string(raw), permissionHash(raw)); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, target)
	if err != nil || !reflect.DeepEqual(snapshot.Bindings, after.Bindings) || !reflect.DeepEqual(snapshot.Grants, after.Grants) {
		t.Fatal("publishing preset silently expanded old authority", err)
	}
	// A permission administrator delegated only run cannot truncate the five-action operator preset.
	appointment := f.command(2, "appoint-limited-admin")
	appointment.ExpectedRevision = second.Revision
	appointment = f.authenticate(t, 0, appointment)
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], appointment); err != nil {
		t.Fatal(err)
	}
	limited := Delegation{ID: target + "-limited-delegation", SubjectID: target, Scope: scope, Roles: []string{"operator"}, Actions: []string{"run"}, Resources: []string{"fixture-installation"}, DataScopeTypes: []string{"owner"}, ManagementActions: []string{"authorization.change"}, MaxDurationSeconds: 3600, Status: "active", Revision: 1}
	raw, _ = json.Marshal(limited)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,payload) VALUES(?,?,?,?,?,'active',1,?)`), limited.ID, target, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw)); err != nil {
		t.Fatal(err)
	}
	newUser := target + "-ordinary"
	if err := f.store.CreatePrincipal(f.ctx, Principal{ID: newUser, Type: PrincipalUser, TenantID: scope.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), newUser); err != nil {
		t.Fatal(err)
	}
	tx, err = f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := persistMembershipMutation(f.ctx, tx, Membership{ID: newUser + "-member", SubjectID: newUser, Scope: scope, Status: "active", Revision: 1}, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	partial := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: newUser, ExpectedRevision: 1, IdempotencyKey: "partial-preset", Reason: "must reject whole preset", Preset: &PresetSelection{Code: "operator", Version: 1, Scope: scope, ResourceIDs: []string{"fixture-installation"}, Validity: Validity{ExpiresAt: &expires}}}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[2], partial); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("insufficient delegation truncated preset", err)
	}
	partial = preview(f.actors[0], partial)
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[2], partial); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("insufficient delegation committed preset", err)
	}
	after, err = f.store.PermissionSnapshot(f.ctx, PrincipalUser, newUser)
	if err != nil || after.Principal.Revision != 1 || len(after.Bindings) != 0 || len(after.Grants) != 0 {
		t.Fatal("limited delegation partially granted identity or resources", after, err)
	}
}
