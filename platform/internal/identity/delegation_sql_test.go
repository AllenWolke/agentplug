package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLDelegationRevocationFencesPendingAuthorization(t *testing.T) {
	f := newAdministratorFixture(t)
	appointment := f.authenticate(t, 0, f.command(2, "permission-admin"))
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], appointment); err != nil {
		t.Fatal(err)
	}
	scope := appointment.Scope
	d := Delegation{ID: f.actors[2].PrincipalID + "-delegation", SubjectID: f.actors[2].PrincipalID, Scope: scope, Roles: []string{"operator"}, ManagementActions: []string{"authorization.change"}, MaxDurationSeconds: 3600, AllowPermanent: true, Status: "active", Revision: 1}
	command := DelegationCommand{SubjectID: d.SubjectID, ExpectedRevision: 2, IdempotencyKey: "delegate", Reason: "operate within selected application", Delegation: &d}
	authenticate := func(command DelegationCommand) DelegationCommand {
		t.Helper()
		digest, err := DelegationCommandDigest(command)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := f.store.CreateLocalStepUp(f.ctx, f.actors[0], StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "delegation.manage", RequestDigest: digest})
		if err != nil {
			t.Fatal(err)
		}
		command.StepUpToken = proof.Token
		return command
	}
	command = authenticate(command)
	if _, err := f.store.ChangeDelegation(f.ctx, f.actors[0], command); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ChangeDelegation(f.ctx, f.actors[0], command); err != nil {
		t.Fatal("retry denied", err)
	}
	if _, err := f.store.CreateLocalStepUp(f.ctx, f.actors[2], StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "delegation.manage", RequestDigest: command.RequestDigestForTest(t)}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("permission administrator can redelegate", err)
	}
	user := f.actors[2].PrincipalID + "-operator"
	if err := f.store.CreatePrincipal(f.ctx, Principal{ID: user, Type: PrincipalUser, TenantID: scope.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), user); err != nil {
		t.Fatal(err)
	}
	member := Membership{ID: user + "-member", SubjectID: user, Scope: scope, Status: "active", Revision: 1}
	raw, _ := json.Marshal(member)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), member.ID, user, scope.TenantID, scope.DepartmentID, scope.ApplicationID, string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: user, ExpectedRevision: 1, IdempotencyKey: "pending-role", Reason: "selected operator role", Bindings: []RoleBinding{{ID: user + "-binding", SubjectID: user, RoleCode: "operator", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "direct"}}}
	plan, err := f.store.PreviewAuthorizationChange(f.ctx, f.actors[2], change)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], scope, "", 1, 2)
	if err != nil || page.Total != 4 || len(page.Items) != 2 {
		t.Fatal("scoped directory pagination failed", page, err)
	}
	for _, p := range page.Items {
		if len(p.Roles) != 0 || len(p.Groups) != 0 {
			t.Fatal("directory leaked legacy roles")
		}
	}
	if _, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], ManagementScope{Type: "tenant", TenantID: scope.TenantID}, "", 1, 20); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("app administrator read entire tenant", err)
	}
	change.PlanDigest = plan.Digest
	change.PlanExpiresAt = plan.ExpiresAt
	revoke := authenticate(DelegationCommand{SubjectID: d.SubjectID, ExpectedRevision: 3, IdempotencyKey: "revoke", Reason: "revoke authorization delegation", RevokeDelegationID: d.ID})
	fault := errors.New("audit unavailable")
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return fault })
	if _, err := f.store.ChangeDelegation(f.ctx, f.actors[0], revoke); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, d.SubjectID)
	if err != nil || snapshot.Delegations[0].Status != "active" {
		t.Fatal("revocation partially committed", err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	if _, err := f.store.ChangeDelegation(f.ctx, f.actors[0], revoke); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CommitAuthorizationChange(f.ctx, f.actors[2], change); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("pending change survived delegation revocation", err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_role_binding WHERE subject_id=?`), user).Scan(&count); err != nil || count != 0 {
		t.Fatal("revoked delegation issued role", err)
	}
}

func (command DelegationCommand) RequestDigestForTest(t *testing.T) string {
	t.Helper()
	digest, err := DelegationCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
