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

type EnrollmentPermissionApproval struct {
	EnrollmentID     string                    `json:"enrollment_id"`
	ExpectedRevision uint64                    `json:"expected_revision"`
	OperatorIdentity bool                      `json:"operator_identity"`
	Grants           []enrollmentDecisionGrant `json:"grants"`
	Validity
	IdempotencyKey string    `json:"idempotency_key"`
	Reason         string    `json:"reason"`
	PlanDigest     string    `json:"plan_digest,omitempty"`
	PlanExpiresAt  time.Time `json:"plan_expires_at,omitempty"`
}

func enrollmentApprovalDigest(c EnrollmentPermissionApproval) (string, error) {
	if c.EnrollmentID == "" || len(c.EnrollmentID) > 64 || c.ExpectedRevision == 0 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 500 || len(c.Grants) > 16 || c.Validity.Validate() != nil || len(c.Grants) > 0 && !c.OperatorIdentity {
		return "", ErrInvalidResource
	}
	c.PlanDigest, c.PlanExpiresAt = "", time.Time{}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func permissionEnrollment(ctx context.Context, reader permissionReader, id string) (Enrollment, error) {
	return scanEnrollment(reader.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at FROM platform_identity_enrollment WHERE id=?`), id))
}

func authorizeEnrollmentApproval(owner PermissionSnapshot, actor sharedkernel.Scope, item Enrollment, validity Validity, now time.Time) error {
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
	if administrationKind(owner, now) == "department" && departmentAgentPolicyFor(owner, scope) != nil && departmentAdministrationAllows(owner, scope, "access_request.decide", "", "", DataScope{}, validity, now) {
		return nil
	}
	for _, b := range owner.Bindings {
		if b.RoleCode == "super_admin" && slices.Contains(decision.BindingIDs, b.ID) {
			return nil
		}
	}
	for _, d := range owner.Delegations {
		if d.Covers(actor.PrincipalID, "access_request.decide", "", "", "", scope, DataScope{}, validity, now) {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (s *SQLStore) enrollmentApprovalChange(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, item Enrollment, c EnrollmentPermissionApproval) (AuthorizationChangeCommand, error) {
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return AuthorizationChangeCommand{}, err
	}
	if err := authorizeEnrollmentApproval(owner, actor, item, c.Validity, s.clock().UTC()); err != nil {
		return AuthorizationChangeCommand{}, err
	}
	if item.Status != EnrollmentPending || item.Revision != c.ExpectedRevision || item.VerifiedAt == nil {
		return AuthorizationChangeCommand{}, ErrIdentityConflict
	}
	scope := ManagementScope{Type: "application", TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: item.Username, ExpectedRevision: 1, IdempotencyKey: c.IdempotencyKey, Reason: c.Reason, Memberships: []MembershipMutation{{ID: "member-" + permissionHash([]byte(item.ID)), Scope: scope, Status: "active", Validity: c.Validity}}}
	if c.OperatorIdentity {
		change.Bindings = []RoleBinding{{ID: "binding-" + permissionHash([]byte(item.ID)), SubjectID: item.Username, RoleCode: "operator", RoleVersion: 1, Scope: scope, Validity: c.Validity, Status: "active", Revision: 1, SourceID: "enrollment:" + item.ID}}
	}
	seen := map[string]bool{}
	for _, grant := range c.Grants {
		if grant.AgentInstanceID == "" || seen[grant.AgentInstanceID] || len(grant.Actions) == 0 || len(grant.Actions) > 16 || s.permissionResourceResolver == nil {
			return AuthorizationChangeCommand{}, ErrInvalidResource
		}
		seen[grant.AgentInstanceID] = true
		installation, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}, grant.AgentInstanceID)
		if err != nil {
			return AuthorizationChangeCommand{}, err
		}
		if !slices.Contains(item.RequestedAgentIDs, installation.AgentID) {
			return AuthorizationChangeCommand{}, ErrPermissionDenied
		}
		actions := normalizeEnrollmentActions(grant.Actions)
		if len(actions) != len(grant.Actions) {
			return AuthorizationChangeCommand{}, ErrInvalidResource
		}
		for _, action := range actions {
			g := Grant{ID: enrollmentGrantID(item.ID, grant.AgentInstanceID, action), SubjectType: PrincipalUser, SubjectID: item.Username, TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, AgentInstanceID: grant.AgentInstanceID, ResourceType: "agent_installation", ResourceID: grant.AgentInstanceID, Action: action, Effect: "allow", Status: "active", Revision: 1, Validity: c.Validity, SourceID: "enrollment:" + item.ID, DataScope: DataScope{Type: "owner"}}
			change.Grants = append(change.Grants, g)
		}
	}
	return change, nil
}

func (s *SQLStore) PreviewEnrollmentPermissionApproval(ctx context.Context, actor sharedkernel.Scope, c EnrollmentPermissionApproval) (AuthorizationChangePlan, error) {
	digest, err := enrollmentApprovalDigest(c)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	defer tx.Rollback()
	item, err := permissionEnrollment(ctx, tx, c.EnrollmentID)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	change, err := s.enrollmentApprovalChange(ctx, tx, actor, item, c)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE principal_type='user' AND id=?`), item.Username).Scan(&count); err != nil {
		return AuthorizationChangePlan{}, err
	}
	if count != 0 {
		return AuthorizationChangePlan{}, ErrIdentityConflict
	}
	target := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: item.Username, TenantID: item.TenantID, IsActive: true, Revision: 1, Roles: []string{}, Groups: []string{}}, Mode: "v2", Memberships: []Membership{}, Bindings: []RoleBinding{}, Grants: []Grant{}, Delegations: []Delegation{}}
	plan, err := s.planAuthorizationChangeTarget(ctx, tx, actor, change, s.clock().UTC().Add(5*time.Minute), &target)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	plan.Digest = permissionHash([]byte(plan.Digest + "\x00" + digest))
	return plan, tx.Commit()
}

func (s *SQLStore) ApproveEnrollmentPermission(ctx context.Context, actor sharedkernel.Scope, c EnrollmentPermissionApproval) (AuthorizationChangeReceipt, error) {
	if s == nil || s.db == nil || s.authorizationChangeRecorder == nil || s.enrollmentDecisionRecorder == nil {
		return AuthorizationChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	digest, err := enrollmentApprovalDigest(c)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	key := permissionHash([]byte("enrollment.approve\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if digest != priorDigest {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
		}
		var receipt AuthorizationChangeReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		item, err := permissionEnrollment(ctx, tx, c.EnrollmentID)
		if err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if err := authorizeEnrollmentApproval(owner, actor, item, c.Validity, s.clock().UTC()); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AuthorizationChangeReceipt{}, err
	}
	var revision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), actor.PrincipalID).Scan(&revision); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	item, err := scanEnrollment(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at FROM platform_identity_enrollment WHERE id=? FOR UPDATE`), c.EnrollmentID))
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	change, err := s.enrollmentApprovalChange(ctx, tx, actor, item, c)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	var passwordHash string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT password_hash FROM platform_identity_enrollment WHERE id=?`), item.ID).Scan(&passwordHash); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if passwordHash == "" {
		return AuthorizationChangeReceipt{}, ErrIdentityConflict
	}
	now := s.clock().UTC()
	account := PrincipalCreationCommand{Username: item.Username, DisplayName: item.DisplayName, Scope: change.Memberships[0].Scope}
	if err := insertPermissionPrincipalTx(ctx, tx, account, passwordHash, now); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	plan, err := s.planAuthorizationChange(ctx, tx, actor, change, c.PlanExpiresAt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if c.PlanDigest == "" || c.PlanDigest != permissionHash([]byte(plan.Digest+"\x00"+digest)) {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	change.PlanDigest, change.PlanExpiresAt = plan.Digest, plan.ExpiresAt
	receipt, err := s.commitAuthorizationChangeTx(ctx, tx, actor, change, key, digest)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status='approved',reviewed_by=?,reviewed_at=?,public_comment=?,password_hash='',verify_token_hash='',verify_expires_at=NULL,revision=revision+1,updated_at=? WHERE id=? AND status=? AND revision=?`), actor.PrincipalID, now, c.Reason, now, item.ID, EnrollmentPending, c.ExpectedRevision)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return AuthorizationChangeReceipt{}, ErrIdentityConflict
	}
	decision := EnrollmentDecision{EnrollmentID: item.ID, TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, SubjectID: item.Username, ReviewerID: actor.PrincipalID, Status: EnrollmentApproved, Comment: c.Reason, Revision: item.Revision + 1, TraceID: actor.TraceID, OccurredAt: now}
	if err := s.enrollmentDecisionRecorder(ctx, tx, actor, decision); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

type enrollmentPermissionApprover interface {
	PreviewEnrollmentPermissionApproval(context.Context, sharedkernel.Scope, EnrollmentPermissionApproval) (AuthorizationChangePlan, error)
	ApproveEnrollmentPermission(context.Context, sharedkernel.Scope, EnrollmentPermissionApproval) (AuthorizationChangeReceipt, error)
}

func (m *Module) enrollmentPermissionApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(enrollmentPermissionApprover)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	var c EnrollmentPermissionApproval
	if decode(r, &c) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/enrollments:preview-approval" {
		plan, err := repo.PreviewEnrollmentPermissionApproval(r.Context(), actor.Scope, c)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := repo.ApproveEnrollmentPermission(r.Context(), actor.Scope, c)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
