package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type enrollmentFixtureResolver struct{}

func (enrollmentFixtureResolver) ResolveAgentInstallation(_ context.Context, _ sharedkernel.Scope, id string) (AgentInstallation, error) {
	if id == "fixture-installation" {
		return AgentInstallation{AgentID: "requested-agent"}, nil
	}
	if id == "outside-installation" {
		return AgentInstallation{AgentID: "unrequested-agent"}, nil
	}
	return AgentInstallation{}, ErrAgentInstallationNotFound
}

func pendingPermissionEnrollment(t *testing.T, f administratorFixture, id, username string) EnrollmentPermissionApproval {
	t.Helper()
	var hash string
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT password_hash FROM platform_identity_local_credential WHERE principal_id=?`), f.actors[0].PrincipalID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	a := f.actors[0]
	_, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_enrollment(id,username,display_name,contact_masked,contact_hash,password_hash,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,status_token_hash,verify_token_hash,verified_at,revision,created_at,updated_at) VALUES(?,?,'Fixture user','f***@example.org',?,?,?,?,?,'fixture registration','["requested-agent"]',?,?,'',?,2,?,?)`), id, username, permissionHash([]byte(id)), hash, a.TenantID, a.DepartmentID, a.ApplicationID, EnrollmentPending, permissionHash([]byte(id+"status")), f.now, f.now, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return EnrollmentPermissionApproval{EnrollmentID: id, ExpectedRevision: 2, IdempotencyKey: id, Reason: "approve verified fixture registration"}
}

func previewPermissionEnrollment(t *testing.T, f administratorFixture, c EnrollmentPermissionApproval) EnrollmentPermissionApproval {
	t.Helper()
	plan, err := f.store.PreviewEnrollmentPermissionApproval(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	return c
}

func TestSQLEnrollmentPermissionApproval(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error { return nil })
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	identityOnly := previewPermissionEnrollment(t, f, pendingPermissionEnrollment(t, f, "identity-only", "enrollment.identity.user"))
	receipt, err := f.store.ApproveEnrollmentPermission(f.ctx, f.actors[0], identityOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Change.Bindings) != 0 || len(receipt.Change.Grants) != 0 || len(receipt.Memberships) != 1 {
		t.Fatal("identity-only approval granted business authority", receipt)
	}
	if _, err := f.store.VerifyEnrollmentCredentials(f.ctx, receipt.SubjectID, "fixture-administrator-password"); err != nil {
		t.Fatal("approved identity cannot login", err)
	}
	prior, err := f.store.ApproveEnrollmentPermission(f.ctx, f.actors[0], identityOnly)
	if err != nil || prior.ID != receipt.ID {
		t.Fatal("approval retry failed", prior, err)
	}
	withGrant := pendingPermissionEnrollment(t, f, "with-grant", "enrollment.operator.user")
	withGrant.OperatorIdentity = true
	withGrant.Grants = []enrollmentDecisionGrant{{AgentInstanceID: "outside-installation", Actions: []string{"run"}}}
	if _, err := f.store.PreviewEnrollmentPermissionApproval(f.ctx, f.actors[0], withGrant); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("unrequested agent accepted", err)
	}
	withGrant.Grants[0].AgentInstanceID = "fixture-installation"
	withGrant = previewPermissionEnrollment(t, f, withGrant)
	receipt, err = f.store.ApproveEnrollmentPermission(f.ctx, f.actors[0], withGrant)
	if err != nil || len(receipt.Change.Grants) != 1 || len(receipt.Change.Bindings) != 1 {
		t.Fatal("requested subset not applied", receipt, err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, receipt.SubjectID)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: "run", Scope: receipt.Memberships[0].Scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || !decision.Allowed {
		t.Fatal("exact approved operation unavailable", decision, err)
	}
	decision, err = EvaluatePermission(snapshot, PermissionQuery{Action: "history.export", Scope: receipt.Memberships[0].Scope, ResourceType: "agent_installation", ResourceID: "fixture-installation", Now: f.now})
	if err != nil || decision.Allowed {
		t.Fatal("unapproved operation allowed", decision, err)
	}
	rollback := previewPermissionEnrollment(t, f, pendingPermissionEnrollment(t, f, "rollback", "enrollment.rollback.user"))
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error {
		return errors.New("decision audit unavailable")
	})
	if _, err := f.store.ApproveEnrollmentPermission(f.ctx, f.actors[0], rollback); err == nil {
		t.Fatal("approval audit failure committed")
	}
	item, err := permissionEnrollment(f.ctx, f.db, rollback.EnrollmentID)
	if err != nil || item.Status != EnrollmentPending || item.Revision != 2 {
		t.Fatal("request transition was not rolled back", item, err)
	}
	var count int
	for _, query := range []string{`SELECT COUNT(*) FROM platform_identity_principal WHERE id=?`, `SELECT COUNT(*) FROM platform_identity_local_credential WHERE principal_id=?`, `SELECT COUNT(*) FROM platform_identity_membership WHERE subject_id=?`, `SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id=?`} {
		if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(query), item.Username).Scan(&count); err != nil || count != 0 {
			t.Fatal("approval left partial account", query, count, err)
		}
	}
	self := pendingPermissionEnrollment(t, f, "self-review", f.actors[0].PrincipalID)
	if _, err := f.store.PreviewEnrollmentPermissionApproval(f.ctx, f.actors[0], self); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("self review allowed", err)
	}
	if _, err := f.store.PreviewEnrollmentPermissionApproval(f.ctx, f.actors[2], rollback); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user could approve", err)
	}
	if _, err := f.store.ApproveEnrollment(f.ctx, EnrollmentScope{TenantID: f.actors[0].TenantID, DepartmentID: f.actors[0].DepartmentID, ApplicationID: f.actors[0].ApplicationID}, rollback.EnrollmentID, f.actors[0].PrincipalID, 2, "legacy bypass attempt", "", []EnrollmentGrant{{AgentID: "requested-agent", AgentInstanceID: "fixture-installation", Actions: []string{"run"}}}, time.Now().UTC()); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("v2 approver used legacy grant path", err)
	}
	var passwordLength, verificationLength int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT LENGTH(password_hash),LENGTH(verify_token_hash) FROM platform_identity_enrollment WHERE id=?`), withGrant.EnrollmentID).Scan(&passwordLength, &verificationLength); err != nil || passwordLength != 0 || verificationLength != 0 {
		t.Fatal("approved request retained credential material", passwordLength, verificationLength, err)
	}
}
