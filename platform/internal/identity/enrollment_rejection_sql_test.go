package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func pendingRejection(t *testing.T, f administratorFixture, id string) EnrollmentRejectionCommand {
	t.Helper()
	c := pendingPermissionEnrollment(t, f, id, "reject."+id)
	return EnrollmentRejectionCommand{EnrollmentID: c.EnrollmentID, ExpectedRevision: c.ExpectedRevision, IdempotencyKey: c.IdempotencyKey, Reason: "verified registration rejected"}
}

func previewRejection(t *testing.T, f administratorFixture, c EnrollmentRejectionCommand) EnrollmentRejectionCommand {
	t.Helper()
	p, err := f.store.PreviewEnrollmentRejection(f.ctx, f.actors[0], c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	return c
}

func TestSQLEnrollmentRejection(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error { return nil })
	c := previewRejection(t, f, pendingRejection(t, f, "normal"))
	receipt, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], c)
	if err != nil || receipt.Status != EnrollmentRejected || receipt.Revision != 3 {
		t.Fatal(receipt, err)
	}
	var passwordLength, tokenLength, count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT LENGTH(password_hash),LENGTH(verify_token_hash) FROM platform_identity_enrollment WHERE id=?`), c.EnrollmentID).Scan(&passwordLength, &tokenLength); err != nil || passwordLength != 0 || tokenLength != 0 {
		t.Fatal("rejection retained authentication material", err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE id=?`), receipt.Username).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejection created an account", err)
	}
	prior, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], c)
	if err != nil || prior.ID != receipt.ID {
		t.Fatal("rejection retry changed result", prior, err)
	}
	changed := c
	changed.Reason = "a different rejection reason"
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], changed); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("same key changed request accepted", err)
	}
	rollback := previewRejection(t, f, pendingRejection(t, f, "rollback"))
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error {
		return errors.New("audit unavailable")
	})
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], rollback); err == nil {
		t.Fatal("rejection audit failure committed")
	}
	item, err := permissionEnrollment(f.ctx, f.db, rollback.EnrollmentID)
	if err != nil || item.Status != EnrollmentPending || item.Revision != 2 {
		t.Fatal("rejection rollback lost request", item, err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_authorization_change WHERE subject_id=?`), item.Username).Scan(&count); err != nil || count != 0 {
		t.Fatal("rollback retained receipt", count, err)
	}
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error { return nil })
	withdrawn := previewRejection(t, f, pendingRejection(t, f, "withdrawn"))
	if _, err := f.store.WithdrawEnrollment(f.ctx, withdrawn.EnrollmentID, permissionHash([]byte(withdrawn.EnrollmentID+"status")), 2, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], withdrawn); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("withdrawn request rejected with stale preview", err)
	}
	self := pendingPermissionEnrollment(t, f, "self", f.actors[0].PrincipalID)
	if _, err := f.store.PreviewEnrollmentRejection(f.ctx, f.actors[0], EnrollmentRejectionCommand{EnrollmentID: self.EnrollmentID, ExpectedRevision: 2, IdempotencyKey: "self", Reason: "self review attempt"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("self rejection allowed", err)
	}
	if _, err := f.store.PreviewEnrollmentRejection(f.ctx, f.actors[2], rollback); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user rejected registration", err)
	}
	if _, err := f.store.RejectEnrollment(f.ctx, EnrollmentScope{TenantID: f.actors[0].TenantID, DepartmentID: f.actors[0].DepartmentID, ApplicationID: f.actors[0].ApplicationID}, rollback.EnrollmentID, f.actors[0].PrincipalID, 2, "old route", "", f.now); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("v2 actor used legacy rejection", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id=? AND principal_type='user'`), f.actors[0].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[0], c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("disabled actor recovered receipt", err)
	}
}

func TestSQLEnrollmentApprovalAndRejectionRace(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error { return nil })
	a := previewPermissionEnrollment(t, f, pendingPermissionEnrollment(t, f, "race", "enrollment.race.user"))
	c := EnrollmentRejectionCommand{EnrollmentID: a.EnrollmentID, ExpectedRevision: a.ExpectedRevision, IdempotencyKey: "race-reject", Reason: "second reviewer rejects registration"}
	p, err := f.store.PreviewEnrollmentRejection(f.ctx, f.actors[1], c)
	if err != nil {
		t.Fatal(err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	var wg sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := f.store.ApproveEnrollmentPermission(f.ctx, f.actors[0], a)
		results <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := f.store.RejectEnrollmentPermission(f.ctx, f.actors[1], c)
		results <- err
	}()
	close(start)
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrIdentityConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("competing decisions did not yield one winner", success, conflicts)
	}
	item, err := permissionEnrollment(f.ctx, f.db, a.EnrollmentID)
	if err != nil || item.Revision != 3 {
		t.Fatal(item, err)
	}
	var accounts int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE id=?`), item.Username).Scan(&accounts); err != nil {
		t.Fatal(err)
	}
	if item.Status == EnrollmentApproved && accounts != 1 || item.Status == EnrollmentRejected && accounts != 0 {
		t.Fatal("decision and account disagree", item.Status, accounts)
	}
}

func TestSQLEnrollmentRejectionTemporaryDelegation(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetEnrollmentDecisionRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error { return nil })
	a := f.actors[2]
	scope := ManagementScope{Type: "application", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	b := RoleBinding{ID: "fixture-permission-admin", SubjectID: a.PrincipalID, RoleCode: "permission_admin", RoleVersion: 1, Scope: scope, Status: "active", Revision: 1, SourceID: "fixture"}
	if err := insertRoleBinding(f.ctx, tx, b); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	c := pendingRejection(t, f, "delegated")
	if _, err := f.store.PreviewEnrollmentRejection(f.ctx, a, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("permission-admin role without delegation allowed rejection", err)
	}
	expiry := f.now.Add(time.Hour)
	d := Delegation{ID: "fixture-temporary-decision", SubjectID: a.PrincipalID, Scope: scope, ManagementActions: []string{"access_request.decide"}, MaxDurationSeconds: 3600, Validity: Validity{ExpiresAt: &expiry}, Status: "active", Revision: 1}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, a.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDelegationBoundary(d, snapshot, f.now); err != nil {
		t.Fatal("fixture delegation is not issuable", err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,expires_at,payload) VALUES(?,?,?,?,?,'active',1,?,?)`), d.ID, a.PrincipalID, a.TenantID, a.DepartmentID, a.ApplicationID, expiry, string(raw)); err != nil {
		t.Fatal(err)
	}
	p, err := f.store.PreviewEnrollmentRejection(f.ctx, a, c)
	if err != nil {
		t.Fatal("temporary decision-only delegation required permanent grant authority", err)
	}
	c.PlanDigest, c.PlanExpiresAt = p.Digest, p.ExpiresAt
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, a, c); err != nil {
		t.Fatal(err)
	}
	f.store.clock = func() time.Time { return expiry }
	if _, err := f.store.RejectEnrollmentPermission(f.ctx, a, c); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("expired delegation recovered old decision receipt", err)
	}
}
