package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type PermissionRequestDecision struct {
	RequestID               string    `json:"request_id"`
	ExpectedRevision        uint64    `json:"expected_revision"`
	ExpectedSubjectRevision uint64    `json:"expected_subject_revision"`
	Decision                string    `json:"decision"`
	ApprovedItemIDs         []string  `json:"approved_item_ids"`
	IdempotencyKey          string    `json:"idempotency_key"`
	Reason                  string    `json:"reason"`
	PlanDigest              string    `json:"plan_digest,omitempty"`
	PlanExpiresAt           time.Time `json:"plan_expires_at,omitempty"`
}

type PermissionRequestDecisionPlan struct {
	Digest        string                    `json:"plan_digest"`
	ExpiresAt     time.Time                 `json:"plan_expires_at"`
	Change        PermissionRequestDecision `json:"change"`
	Items         []PermissionRequestItem   `json:"items"`
	Authorization *AuthorizationChangePlan  `json:"authorization,omitempty"`
}

type PermissionRequestDecisionReceipt struct {
	Request       PermissionRequest           `json:"request"`
	Authorization *AuthorizationChangeReceipt `json:"authorization,omitempty"`
}

func permissionRequestDecisionDigest(c PermissionRequestDecision) (string, error) {
	if c.RequestID == "" || len(c.RequestID) > 128 || c.ExpectedRevision == 0 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 || len(c.ApprovedItemIDs) > 32 || c.Decision != "approved" && c.Decision != "rejected" || c.Decision == "approved" && (len(c.ApprovedItemIDs) == 0 || c.ExpectedSubjectRevision == 0) || c.Decision == "rejected" && len(c.ApprovedItemIDs) != 0 {
		return "", ErrInvalidResource
	}
	seen := map[string]bool{}
	for _, id := range c.ApprovedItemIDs {
		if id == "" || seen[id] {
			return "", ErrInvalidResource
		}
		seen[id] = true
	}
	c.PlanDigest, c.PlanExpiresAt = "", time.Time{}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func authorizePermissionRequestDecision(owner PermissionSnapshot, actor sharedkernel.Scope, request PermissionRequest, now time.Time) error {
	if strings.EqualFold(actor.PrincipalID, request.SubjectID) {
		return ErrPermissionDenied
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "access_request.decide", Scope: request.Scope, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	if companyAdministrationAllows(owner, request.Scope, "access_request.decide", now) {
		return nil
	}
	if administrationKind(owner, now) == "department" && departmentAgentPolicyFor(owner, request.Scope) != nil {
		return nil
	}
	for _, b := range owner.Bindings {
		if b.RoleCode == "super_admin" && slices.Contains(decision.BindingIDs, b.ID) {
			return nil
		}
	}
	for _, d := range owner.Delegations {
		if d.SubjectID == actor.PrincipalID && d.Status == "active" && d.Effective(now) && d.Scope.Contains(request.Scope) && slices.Contains(d.ManagementActions, "access_request.decide") {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (s *SQLStore) planPermissionRequestDecision(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, c PermissionRequestDecision, deadline time.Time) (PermissionRequestDecisionPlan, error) {
	if _, err := permissionRequestDecisionDigest(c); err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	request, err := permissionRequestFromRow(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=?`), c.RequestID))
	if err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	now := s.clock().UTC()
	if err := authorizePermissionRequestDecision(owner, actor, request, now); err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	if err := validatePermissionScope(ctx, tx, request.Scope); err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	if request.Status != "pending" || request.Revision != c.ExpectedRevision {
		return PermissionRequestDecisionPlan{}, ErrIdentityConflict
	}
	if !deadline.After(now) || deadline.After(now.Add(5*time.Minute)) {
		return PermissionRequestDecisionPlan{}, ErrPermissionPlanStale
	}
	items := append([]PermissionRequestItem(nil), request.Items...)
	change := AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: request.SubjectID, ExpectedRevision: c.ExpectedSubjectRevision, IdempotencyKey: c.IdempotencyKey, Reason: c.Reason}
	matched := 0
	for i := range items {
		item := &items[i]
		item.Outcome = "rejected"
		if !slices.Contains(c.ApprovedItemIDs, item.ID) {
			continue
		}
		matched++
		item.Outcome = "approved"
		if item.ExpiresAt != nil && !item.ExpiresAt.After(now) {
			return PermissionRequestDecisionPlan{}, ErrPermissionPlanStale
		}
		id := permissionHash([]byte(request.ID + "\x00" + item.ID))
		source := "request:" + request.ID + ":" + item.ID
		switch item.Kind {
		case "role":
			change.Bindings = append(change.Bindings, RoleBinding{ID: "binding-" + id, SubjectID: request.SubjectID, RoleCode: item.RoleCode, RoleVersion: item.RoleVersion, Scope: item.Scope, Validity: item.Validity, Status: "active", Revision: 1, SourceID: source})
		case "resource":
			grant, err := permissionRequestResourceGrant(*item, request.SubjectID)
			if err != nil {
				return PermissionRequestDecisionPlan{}, err
			}
			grant.ID, grant.SourceID = "grant-"+id, source
			change.Grants = append(change.Grants, grant)
		default:
			return PermissionRequestDecisionPlan{}, ErrInvalidResource
		}
	}
	if matched != len(c.ApprovedItemIDs) {
		return PermissionRequestDecisionPlan{}, ErrInvalidResource
	}
	plan := PermissionRequestDecisionPlan{ExpiresAt: deadline, Change: c, Items: items}
	if c.Decision == "approved" {
		authorization, err := s.planAuthorizationChange(ctx, tx, actor, change, deadline)
		if err != nil {
			return plan, err
		}
		plan.Authorization = &authorization
	}
	ownerDigest, err := PermissionSnapshotDigest(owner)
	if err != nil {
		return plan, err
	}
	plan.Change.PlanDigest, plan.Change.PlanExpiresAt = "", time.Time{}
	raw, err := json.Marshal([]any{plan, request, ownerDigest})
	if err != nil {
		return plan, err
	}
	plan.Digest = permissionHash(raw)
	return plan, nil
}

func (s *SQLStore) PreviewPermissionRequestDecision(ctx context.Context, actor sharedkernel.Scope, c PermissionRequestDecision) (PermissionRequestDecisionPlan, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return PermissionRequestDecisionPlan{}, err
	}
	defer tx.Rollback()
	plan, err := s.planPermissionRequestDecision(ctx, tx, actor, c, s.clock().UTC().Add(5*time.Minute))
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit()
}

func updatePermissionRequestTx(ctx context.Context, tx *sql.Tx, request PermissionRequest, expected uint64) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_permission_request SET status=?,revision=?,payload=?,updated_at=? WHERE id=? AND status='pending' AND revision=?`), request.Status, request.Revision, string(raw), request.UpdatedAt, request.ID, expected)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrIdentityConflict
	}
	return nil
}

func (s *SQLStore) DecidePermissionRequest(ctx context.Context, actor sharedkernel.Scope, c PermissionRequestDecision) (PermissionRequestDecisionReceipt, error) {
	if s == nil || s.db == nil || s.administrativeRecorder == nil || c.Decision == "approved" && s.authorizationChangeRecorder == nil {
		return PermissionRequestDecisionReceipt{}, ErrPermissionRecorderUnavailable
	}
	if _, err := permissionRequestDecisionDigest(c); err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	receipt, err := s.decidePermissionRequestTx(ctx, tx, actor, c)
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	return receipt, tx.Commit()
}

// A persistent batch uses the same decision service and owns the transaction
// so the decision and its per-item completion state are committed together.
func (s *SQLStore) decidePermissionRequestTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, c PermissionRequestDecision) (PermissionRequestDecisionReceipt, error) {
	digest, err := permissionRequestDecisionDigest(c)
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	key := permissionHash([]byte("permission-request.decide\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
	owner, err := permissionRequestOwner(ctx, tx, actor)
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	var priorDigest string
	var saved []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &saved)
	if err == nil {
		if digest != priorDigest {
			return PermissionRequestDecisionReceipt{}, ErrIdentityConflict
		}
		var receipt PermissionRequestDecisionReceipt
		if err := json.Unmarshal(saved, &receipt); err != nil {
			return receipt, err
		}
		if err := validatePermissionScope(ctx, tx, receipt.Request.Scope); err != nil {
			return receipt, err
		}
		if err := authorizePermissionRequestDecision(owner, actor, receipt.Request, s.clock().UTC()); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return PermissionRequestDecisionReceipt{}, err
	}
	request, err := permissionRequestFromRow(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_identity_permission_request WHERE id=? FOR UPDATE`), c.RequestID))
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	ids := []string{actor.PrincipalID}
	if c.Decision == "approved" {
		ids = append(ids, request.SubjectID)
	}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		var revision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), id).Scan(&revision); err != nil {
			return PermissionRequestDecisionReceipt{}, err
		}
	}
	plan, err := s.planPermissionRequestDecision(ctx, tx, actor, c, c.PlanExpiresAt)
	if err != nil {
		return PermissionRequestDecisionReceipt{}, err
	}
	if c.PlanDigest == "" || c.PlanDigest != plan.Digest {
		return PermissionRequestDecisionReceipt{}, ErrPermissionPlanStale
	}
	receipt := PermissionRequestDecisionReceipt{}
	if plan.Authorization != nil {
		change := plan.Authorization.Command
		change.PlanDigest, change.PlanExpiresAt = plan.Authorization.Digest, plan.Authorization.ExpiresAt
		authorization, err := s.commitAuthorizationChangeTx(ctx, tx, actor, change, key, digest)
		if err != nil {
			return receipt, err
		}
		receipt.Authorization = &authorization
	}
	request.Status, request.Revision, request.ReviewerID, request.Comment, request.UpdatedAt = c.Decision, request.Revision+1, actor.PrincipalID, c.Reason, s.clock().UTC()
	request.Items = plan.Items
	if err := updatePermissionRequestTx(ctx, tx, request, c.ExpectedRevision); err != nil {
		return receipt, err
	}
	receipt.Request = request
	raw, err := json.Marshal(request)
	if err != nil {
		return receipt, err
	}
	event := AdministrativeEvent{ID: "request-decision-" + key, ActorID: actor.PrincipalID, SubjectID: request.SubjectID, Action: "identity.permission_request." + c.Decision, Reason: c.Reason, Revision: request.Revision, OccurredAt: request.UpdatedAt, DetailsDigest: permissionHash(raw)}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return receipt, err
	}
	raw, err = json.Marshal(receipt)
	if err != nil {
		return receipt, err
	}
	if receipt.Authorization != nil {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_authorization_change SET receipt=? WHERE idempotency_hash=?`), string(raw), key)
	} else {
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, request.SubjectID, key, digest, string(raw), request.UpdatedAt)
	}
	if err != nil {
		return receipt, err
	}
	return receipt, nil
}
