package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func creationFixtureCommand(f administratorFixture, name string) PrincipalCreationCommand {
	a := f.actors[0]
	scope := ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}
	return PrincipalCreationCommand{Username: name, DisplayName: "Fixture user", Password: "fixture-user-password", Scope: scope, Preset: &PresetSelection{Code: "operator", Version: 1, Scope: scope}, IdempotencyKey: name, Reason: "create scoped fixture user"} // secret-scan: allow deterministic credential for the isolated, disposable fixture only
}

func previewCreation(t *testing.T, f administratorFixture, c PrincipalCreationCommand) PrincipalCreationCommand {
	t.Helper()
	plan, err := f.store.PreviewPrincipalCreation(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(plan)
	if err != nil || strings.Contains(string(raw), c.Password) || strings.Contains(string(raw), "password_hash") {
		t.Fatal("preview exposed credential", err)
	}
	c.PlanDigest, c.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	return c
}

func TestSQLPermissionPrincipalCreation(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	c := previewCreation(t, f, creationFixtureCommand(f, "member.create.user"))
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE id=?`), c.Username).Scan(&count); err != nil || count != 0 {
		t.Fatal("preview wrote account", count, err)
	}
	receipt, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Revision != 2 || len(receipt.Memberships) != 1 || len(receipt.Change.Bindings) != 1 || len(receipt.Change.Grants) != 0 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, c.Username)
	if err != nil || snapshot.Mode != "v2" || len(snapshot.Principal.Roles) != 0 || len(snapshot.Memberships) != 1 || len(snapshot.Bindings) != 1 {
		t.Fatal("account facts incomplete", snapshot, err)
	}
	if _, err := f.store.VerifyEnrollmentCredentials(f.ctx, c.Username, c.Password); err != nil {
		t.Fatal("new credential unusable", err)
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: "run", Scope: c.Scope, ResourceType: "agent_installation", ResourceID: "ungranted", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("identity-only account gained business access", decision, err)
	}
	prior, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], c)
	if err != nil || prior.ID != receipt.ID {
		t.Fatal("idempotent retry failed", prior, err)
	}
	changed := c
	changed.Password = "changed-fixture-password" // secret-scan: allow deterministic wrong credential for the isolated fixture retry
	if _, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], changed); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("different credential accepted on retry", err)
	}
	changed = previewCreation(t, f, creationFixtureCommand(f, "member.changed.user"))
	changed.DisplayName = "Changed after preview"
	if _, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], changed); !errors.Is(err, ErrPermissionPlanStale) {
		t.Fatal("creation metadata not bound to preview", err)
	}
	rollback := previewCreation(t, f, creationFixtureCommand(f, "member.rollback.user"))
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error {
		return errors.New("audit unavailable")
	})
	if _, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], rollback); err == nil {
		t.Fatal("audit failure committed")
	}
	for _, query := range []string{
		`SELECT COUNT(*) FROM platform_identity_principal WHERE id=?`,
		`SELECT COUNT(*) FROM platform_identity_local_credential WHERE principal_id=?`,
		`SELECT COUNT(*) FROM platform_identity_policy_migration WHERE subject_id=?`,
		`SELECT COUNT(*) FROM platform_identity_membership WHERE subject_id=?`,
		`SELECT COUNT(*) FROM platform_identity_role_binding WHERE subject_id=?`,
		`SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id=?`,
	} {
		if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(query), rollback.Username).Scan(&count); err != nil || count != 0 {
			t.Fatal("creation not fully rolled back", query, count, err)
		}
	}
	denied := creationFixtureCommand(f, "member.denied.user")
	if _, err := f.store.PreviewPrincipalCreation(f.ctx, f.actors[2], denied); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user could preview account creation", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), f.actors[0].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("disabled actor recovered old receipt", err)
	}
}

func TestSQLMembershipRemovalRetainsOtherCoverageAndRejectsStaleCAS(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	c := previewCreation(t, f, creationFixtureCommand(f, "member.covered.user"))
	receipt, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	additional := Membership{ID: "tenant-member", SubjectID: c.Username, Scope: ManagementScope{Type: "tenant", TenantID: c.Scope.TenantID}, Status: "active", Revision: 1}
	if err := persistMembershipMutation(f.ctx, tx, additional, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	member := receipt.Memberships[0]
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: c.Username, ExpectedRevision: 2, IdempotencyKey: "remove-one-coverage", Reason: "remove redundant membership", Memberships: []MembershipMutation{{ID: member.ID, Scope: member.Scope, ExpectedRevision: member.Revision, Status: "revoked"}}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], command)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.AutomaticRevokeBindingIDs) != 0 {
		t.Fatal("other valid coverage ignored", plan)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], command); err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision, command.IdempotencyKey = 3, "stale-membership-revision"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], command); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale membership CAS accepted", err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, c.Username)
	if err != nil || snapshot.Bindings[0].Status != "active" {
		t.Fatal("unrelated authority revoked", snapshot, err)
	}
}

func TestSQLMembershipRemovalPreservesDenyAndPreventsRejoinRevival(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	c := previewCreation(t, f, creationFixtureCommand(f, "member.rejoin.user"))
	receipt, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, effect := range []string{"allow", "deny"} {
		g := Grant{ID: "grant-" + effect, SubjectType: PrincipalUser, SubjectID: c.Username, TenantID: c.Scope.TenantID, DepartmentID: c.Scope.DepartmentID, ApplicationID: c.Scope.ApplicationID, AgentInstanceID: "fixture-agent", ResourceType: "agent_installation", ResourceID: "fixture-agent", Action: "run", Effect: effect, Status: "active", Revision: 1, DataScope: DataScope{Type: "owner"}, SourceID: "fixture"}
		if err := insertPermissionGrant(f.ctx, tx, g, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	member := receipt.Memberships[0]
	command := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: c.Username, ExpectedRevision: 2, IdempotencyKey: "remove-member", Reason: "remove application membership", Memberships: []MembershipMutation{{ID: member.ID, Scope: member.Scope, ExpectedRevision: member.Revision, Status: "revoked"}}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], command)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.AutomaticRevokeBindingIDs) != 1 || len(plan.AutomaticRevokeGrantIDs) != 1 || plan.AutomaticRevokeGrantIDs[0] != "grant-allow" {
		t.Fatal("incorrect automatic revocations", plan)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	removed, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], command)
	if err != nil {
		t.Fatal(err)
	}
	command.ExpectedRevision, command.IdempotencyKey = removed.Revision, "rejoin-member"
	command.Memberships[0].Status, command.Memberships[0].ExpectedRevision = "active", 2
	plan, err = f.store.PreviewAuthorizationChange(f.ctx, f.actors[0], command)
	if err != nil {
		t.Fatal(err)
	}
	command.PlanDigest, command.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[0], command); err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, c.Username)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Memberships[0].Status != "active" || snapshot.Bindings[0].Status != "revoked" {
		t.Fatal("rejoin restored old role", snapshot)
	}
	for _, grant := range snapshot.Grants {
		if grant.Effect == "deny" && grant.Status != "active" || grant.Effect == "allow" && grant.Status != "revoked" {
			t.Fatal("deny lost or allow revived", grant)
		}
	}
}
