package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type EnrollmentRejectionCommand struct {
	EnrollmentID     string    `json:"enrollment_id"`
	ExpectedRevision uint64    `json:"expected_revision"`
	IdempotencyKey   string    `json:"idempotency_key"`
	Reason           string    `json:"reason"`
	PlanDigest       string    `json:"plan_digest,omitempty"`
	PlanExpiresAt    time.Time `json:"plan_expires_at,omitempty"`
}

type EnrollmentRejectionPlan struct {
	Digest    string                     `json:"plan_digest"`
	ExpiresAt time.Time                  `json:"plan_expires_at"`
	Username  string                     `json:"username"`
	Change    EnrollmentRejectionCommand `json:"change"`
}

type EnrollmentRejectionReceipt struct {
	ID           string    `json:"change_id"`
	ActorID      string    `json:"actor_id"`
	EnrollmentID string    `json:"enrollment_id"`
	Username     string    `json:"username"`
	Revision     uint64    `json:"revision"`
	Status       string    `json:"status"`
	Reason       string    `json:"reason"`
	OccurredAt   time.Time `json:"occurred_at"`
}

func enrollmentRejectionDigest(c EnrollmentRejectionCommand) (string, error) {
	if c.EnrollmentID == "" || len(c.EnrollmentID) > 64 || c.ExpectedRevision == 0 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 500 {
		return "", ErrInvalidResource
	}
	c.PlanDigest, c.PlanExpiresAt = "", time.Time{}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func authorizeEnrollmentRejection(owner PermissionSnapshot, actor sharedkernel.Scope, item Enrollment, now time.Time) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || owner.Mode != "v2" || owner.Principal.ID != actor.PrincipalID || owner.Principal.TenantID != actor.TenantID || strings.EqualFold(actor.PrincipalID, item.Username) {
		return ErrPermissionDenied
	}
	scope := ManagementScope{Type: "application", TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "access_request.decide", Scope: scope, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	if companyAdministrationAllows(owner, scope, "access_request.decide", now) {
		return nil
	}
	if administrationKind(owner, now) == "department" && departmentAgentPolicyFor(owner, scope) != nil {
		return nil
	}
	for _, b := range owner.Bindings {
		if b.RoleCode == "super_admin" && slices.Contains(decision.BindingIDs, b.ID) {
			return nil
		}
	}
	// Rejecting an application creates no long-lived authorization. Validate
	// the present delegated management action without inventing a Grant term.
	for _, d := range owner.Delegations {
		if d.SubjectID == actor.PrincipalID && d.Status == "active" && d.Effective(now) && d.Scope.Contains(scope) && slices.Contains(d.ManagementActions, "access_request.decide") {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (s *SQLStore) planEnrollmentRejection(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, c EnrollmentRejectionCommand, deadline time.Time) (EnrollmentRejectionPlan, error) {
	if _, err := enrollmentRejectionDigest(c); err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	item, err := permissionEnrollment(ctx, tx, c.EnrollmentID)
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	now := s.clock().UTC()
	if err := authorizeEnrollmentRejection(owner, actor, item, now); err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	if item.Status != EnrollmentPending || item.Revision != c.ExpectedRevision {
		return EnrollmentRejectionPlan{}, ErrIdentityConflict
	}
	if err := validatePermissionScope(ctx, tx, ManagementScope{Type: "application", TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}); err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return EnrollmentRejectionPlan{}, ErrPermissionPlanStale
	}
	c.PlanDigest, c.PlanExpiresAt = "", time.Time{}
	ownerDigest, err := PermissionSnapshotDigest(owner)
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	raw, err := json.Marshal([]any{c, item, ownerDigest, deadline})
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	return EnrollmentRejectionPlan{Digest: permissionHash(raw), ExpiresAt: deadline, Username: item.Username, Change: c}, nil
}

func (s *SQLStore) PreviewEnrollmentRejection(ctx context.Context, actor sharedkernel.Scope, c EnrollmentRejectionCommand) (EnrollmentRejectionPlan, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	defer tx.Rollback()
	plan, err := s.planEnrollmentRejection(ctx, tx, actor, c, s.clock().UTC().Add(5*time.Minute))
	if err != nil {
		return EnrollmentRejectionPlan{}, err
	}
	return plan, tx.Commit()
}

func (s *SQLStore) RejectEnrollmentPermission(ctx context.Context, actor sharedkernel.Scope, c EnrollmentRejectionCommand) (EnrollmentRejectionReceipt, error) {
	if s == nil || s.db == nil || s.enrollmentDecisionRecorder == nil {
		return EnrollmentRejectionReceipt{}, ErrPermissionRecorderUnavailable
	}
	digest, err := enrollmentRejectionDigest(c)
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	key := permissionHash([]byte("enrollment.reject\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if digest != priorDigest {
			return EnrollmentRejectionReceipt{}, ErrIdentityConflict
		}
		var receipt EnrollmentRejectionReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return EnrollmentRejectionReceipt{}, err
		}
		owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			return EnrollmentRejectionReceipt{}, err
		}
		item, err := permissionEnrollment(ctx, tx, c.EnrollmentID)
		if err != nil {
			return EnrollmentRejectionReceipt{}, err
		}
		if err := validatePermissionScope(ctx, tx, ManagementScope{Type: "application", TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}); err != nil {
			return EnrollmentRejectionReceipt{}, err
		}
		if err := authorizeEnrollmentRejection(owner, actor, item, s.clock().UTC()); err != nil {
			return EnrollmentRejectionReceipt{}, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentRejectionReceipt{}, err
	}
	var revision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), actor.PrincipalID).Scan(&revision); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_enrollment WHERE id=? FOR UPDATE`), c.EnrollmentID).Scan(&revision); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	plan, err := s.planEnrollmentRejection(ctx, tx, actor, c, c.PlanExpiresAt)
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	if c.PlanDigest == "" || c.PlanDigest != plan.Digest {
		return EnrollmentRejectionReceipt{}, ErrPermissionPlanStale
	}
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status='rejected',reviewed_by=?,reviewed_at=?,public_comment=?,password_hash='',verify_token_hash='',verify_expires_at=NULL,revision=revision+1,updated_at=? WHERE id=? AND status=? AND revision=?`), actor.PrincipalID, now, c.Reason, now, c.EnrollmentID, EnrollmentPending, c.ExpectedRevision)
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return EnrollmentRejectionReceipt{}, ErrIdentityConflict
	}
	item, err := permissionEnrollment(ctx, tx, c.EnrollmentID)
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	decision := EnrollmentDecision{EnrollmentID: item.ID, TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, SubjectID: item.Username, ReviewerID: actor.PrincipalID, Status: EnrollmentRejected, Comment: c.Reason, Revision: item.Revision, TraceID: actor.TraceID, OccurredAt: now}
	if err := s.enrollmentDecisionRecorder(ctx, tx, actor, decision); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	receipt := EnrollmentRejectionReceipt{ID: "change-" + key, ActorID: actor.PrincipalID, EnrollmentID: item.ID, Username: item.Username, Revision: item.Revision, Status: item.Status, Reason: c.Reason, OccurredAt: now}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), receipt.ID, actor.PrincipalID, item.Username, key, digest, string(raw), now); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return EnrollmentRejectionReceipt{}, err
	}
	return receipt, nil
}

type enrollmentPermissionRejecter interface {
	PreviewEnrollmentRejection(context.Context, sharedkernel.Scope, EnrollmentRejectionCommand) (EnrollmentRejectionPlan, error)
	RejectEnrollmentPermission(context.Context, sharedkernel.Scope, EnrollmentRejectionCommand) (EnrollmentRejectionReceipt, error)
}

func (m *Module) enrollmentPermissionRejection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(enrollmentPermissionRejecter)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	var c EnrollmentRejectionCommand
	if decode(r, &c) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/enrollments:preview-rejection" {
		plan, err := repo.PreviewEnrollmentRejection(r.Context(), actor.Scope, c)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := repo.RejectEnrollmentPermission(r.Context(), actor.Scope, c)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
