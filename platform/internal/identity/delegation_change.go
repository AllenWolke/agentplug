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

type DelegationCommand struct {
	SubjectID          string      `json:"subject_id"`
	ExpectedRevision   uint64      `json:"expected_revision"`
	IdempotencyKey     string      `json:"idempotency_key"`
	Reason             string      `json:"reason"`
	Delegation         *Delegation `json:"delegation,omitempty"`
	RevokeDelegationID string      `json:"revoke_delegation_id,omitempty"`
	StepUpToken        string      `json:"step_up_token,omitempty"`
}

type DelegationReceipt struct {
	AdministrativeEvent
	RequestDigest string            `json:"request_digest"`
	Command       DelegationCommand `json:"change"`
	Delegation    Delegation        `json:"delegation"`
}

func DelegationCommandDigest(command DelegationCommand) (string, error) {
	command.StepUpToken = ""
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func validateDelegationCommand(command DelegationCommand) error {
	if strings.TrimSpace(command.SubjectID) == "" || command.ExpectedRevision == 0 || command.IdempotencyKey == "" || len(command.IdempotencyKey) > 128 || strings.TrimSpace(command.Reason) == "" || len(command.Reason) > 2000 || (command.Delegation == nil) == (command.RevokeDelegationID == "") {
		return ErrInvalidResource
	}
	return nil
}

func validateDelegationBoundary(d Delegation, target PermissionSnapshot, now time.Time) error {
	if d.ID == "" || d.SubjectID != target.Principal.ID || d.Scope.Validate() != nil || d.Scope.Type == "global" || d.Scope.TenantID != target.Principal.TenantID || d.Status != "active" || d.Revision != 1 || d.Validity.Validate() != nil || (d.ExpiresAt != nil && !d.ExpiresAt.After(now)) || (d.AllowPermanent && d.ExpiresAt != nil) || d.MaxDurationSeconds < 0 || d.MaxDurationSeconds > 10*365*24*3600 || (!d.AllowPermanent && d.MaxDurationSeconds == 0) {
		return ErrInvalidResource
	}
	qualified := false
	departmentQualified := false
	for _, b := range target.Bindings {
		if b.RoleCode == "permission_admin" && b.Status == "active" && b.Effective(now) && b.Scope.Contains(d.Scope) {
			qualified = true
		}
		if b.RoleCode == "department_admin" && b.RoleVersion == 2 && b.Status == "active" && b.Effective(now) && b.Scope.Type == "department" && b.Scope.Contains(d.Scope) {
			qualified = true
			departmentQualified = true
		}
	}
	member := false
	for _, m := range target.Memberships {
		if m.Status == "active" && m.Effective(now) && m.Scope.Contains(d.Scope) {
			member = true
		}
	}
	if !qualified || !member {
		return ErrPermissionDenied
	}
	if departmentQualified && administrationKind(target, now) == "department" {
		for _, role := range d.Roles {
			if !slices.Contains([]string{"operator", "skill_user", "agent_delegate"}, role) {
				return ErrPermissionDenied
			}
		}
		for _, action := range d.Actions {
			if !slices.Contains([]string{"discover", "run", "cancel", "history.read", "history.continue", "skill.load", "agent.delegate", "knowledge.search", "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write"}, action) {
				return ErrPermissionDenied
			}
		}
		for _, data := range d.DataScopeTypes {
			if data != "owner" {
				return ErrPermissionDenied
			}
		}
		for _, action := range d.ManagementActions {
			if !slices.Contains([]string{"authorization.change", "access_request.decide", "membership.manage"}, action) {
				return ErrPermissionDenied
			}
		}
	}
	if len(d.Roles) > 20 || len(d.Actions) > 50 || len(d.Resources)+len(d.ResourceBindings) > 100 || len(d.DataIDs) > 100 || len(d.ManagementActions) == 0 || len(d.ManagementActions) > 4 {
		return ErrInvalidResource
	}
	for _, values := range [][]string{d.Roles, d.Actions, d.Resources, d.DataScopeTypes, d.DataIDs, d.ManagementActions} {
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "*\x00") || seen[value] {
				return ErrInvalidResource
			}
			seen[value] = true
		}
	}
	for _, code := range d.Roles {
		if code == "super_admin" || code == "permission_admin" {
			return ErrPermissionDenied
		}
		found := false
		for _, role := range target.Roles {
			if role.Code == code && role.Assignable {
				found = true
			}
		}
		if !found {
			return ErrInvalidResource
		}
	}
	for _, code := range d.Actions {
		found := false
		for _, action := range BuiltinPermissionActions() {
			if action.Code == code && !action.Management {
				found = true
			}
		}
		if !found {
			return ErrInvalidResource
		}
	}
	if len(d.Actions) > 0 && (len(d.Resources)+len(d.ResourceBindings) == 0 || len(d.DataScopeTypes) == 0) {
		return ErrInvalidResource
	}
	if len(d.Resources)+len(d.ResourceBindings) > 0 && d.Scope.Type != "application" && d.Scope.Type != "agent_installation" {
		return ErrInvalidResource
	}
	seenBindings := map[DelegatedResource]bool{}
	for _, binding := range d.ResourceBindings {
		if !validPermissionResourceID(binding.ResourceID) || !validPermissionResourceID(binding.InstallationID) || seenBindings[binding] {
			return ErrInvalidResource
		}
		seenBindings[binding] = true
		matched := false
		for _, action := range BuiltinPermissionActions() {
			if !action.Management && action.ResourceType == binding.ResourceType && slices.Contains(d.Actions, action.Code) {
				matched = true
			}
		}
		if !matched || binding.ResourceType == "agent_installation" && binding.ResourceID != binding.InstallationID {
			return ErrInvalidResource
		}
	}
	for _, code := range d.DataScopeTypes {
		if !slices.Contains([]string{"owner", "assigned_task", "explicit_set", "approved_organization"}, code) {
			return ErrInvalidResource
		}
	}
	if slices.Contains(d.DataScopeTypes, "explicit_set") && len(d.DataIDs) == 0 {
		return ErrInvalidResource
	}
	if !slices.Contains(d.DataScopeTypes, "explicit_set") && len(d.DataIDs) > 0 {
		return ErrInvalidResource
	}
	for _, code := range d.ManagementActions {
		if !slices.Contains([]string{"authorization.change", "access_request.decide", "membership.manage", "principal.disable"}, code) {
			return ErrPermissionDenied
		}
	}
	return nil
}

// Delegation creates grant-making authority, never a business resource grant.
// Revocation fences pending administrative submissions but preserves grants
// legitimately issued earlier; their persisted DelegationID supports review.
func (s *SQLStore) ChangeDelegation(ctx context.Context, actor sharedkernel.Scope, command DelegationCommand) (DelegationReceipt, error) {
	if s.administrativeRecorder == nil {
		return DelegationReceipt{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) {
		return DelegationReceipt{}, ErrInvalidResource
	}
	if err := validateDelegationCommand(command); err != nil {
		return DelegationReceipt{}, err
	}
	digest, err := DelegationCommandDigest(command)
	if err != nil {
		return DelegationReceipt{}, err
	}
	key := permissionHash([]byte("delegation.manage\x00" + actor.PrincipalID + "\x00" + command.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return DelegationReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return DelegationReceipt{}, err
	}
	ids := []string{actor.PrincipalID, command.SubjectID}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		var revision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), id).Scan(&revision); err != nil {
			return DelegationReceipt{}, err
		}
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DelegationReceipt{}, err
	}
	if err := requireAdministrativeStepUp(owner, "delegation.manage", actor.TenantID, now); err != nil {
		return DelegationReceipt{}, err
	}
	var priorDigest string
	var encoded []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &encoded)
	if err == nil {
		if priorDigest != digest {
			return DelegationReceipt{}, ErrIdentityConflict
		}
		var receipt DelegationReceipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DelegationReceipt{}, err
	}
	target, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, command.SubjectID)
	if err != nil {
		return DelegationReceipt{}, err
	}
	if target.Mode != "v2" || !target.Principal.IsActive {
		return DelegationReceipt{}, ErrPermissionDenied
	}
	if target.Principal.Revision != command.ExpectedRevision {
		return DelegationReceipt{}, ErrIdentityConflict
	}
	if err := consumeStepUp(ctx, tx, actor, command.StepUpToken, "delegation.manage", digest, now); err != nil {
		return DelegationReceipt{}, err
	}
	delegation, err := s.validateDelegationTarget(ctx, tx, target, command, now)
	if err != nil {
		return DelegationReceipt{}, err
	}
	if err := authorizeCompanyDelegation(owner, target, delegation, command.Delegation != nil, now); err != nil {
		return DelegationReceipt{}, err
	}
	if command.Delegation != nil {
		raw, err := json.Marshal(delegation)
		if err != nil {
			return DelegationReceipt{}, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_delegation(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload) VALUES(?,?,?,?,?,'active',1,?,?,?)`), delegation.ID, delegation.SubjectID, delegation.Scope.TenantID, delegation.Scope.DepartmentID, delegation.Scope.ApplicationID, delegation.StartsAt, delegation.ExpiresAt, string(raw)); err != nil {
			return DelegationReceipt{}, identityPersistenceError("create delegation", err)
		}
	} else {
		delegation.Status = "revoked"
		delegation.Revision++
		raw, err := json.Marshal(delegation)
		if err != nil {
			return DelegationReceipt{}, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_delegation SET status='revoked',revision=revision+1,payload=? WHERE id=? AND subject_id=? AND status='active'`), string(raw), delegation.ID, command.SubjectID); err != nil {
			return DelegationReceipt{}, err
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=? AND revision=?`), command.SubjectID, command.ExpectedRevision)
	if err != nil {
		return DelegationReceipt{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return DelegationReceipt{}, err
	}
	if count != 1 {
		return DelegationReceipt{}, ErrIdentityConflict
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET revision=revision+1,epoch=epoch+1 WHERE principal_type='user' AND subject_id=? AND policy_mode='v2'`), command.SubjectID); err != nil {
		return DelegationReceipt{}, err
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, PrincipalUser, command.SubjectID); err != nil {
		return DelegationReceipt{}, err
	}
	command.StepUpToken = ""
	event := AdministrativeEvent{SubjectType: PrincipalUser, ID: "delegation-change-" + key, ActorID: actor.PrincipalID, SubjectID: command.SubjectID, Action: "delegation.manage", Reason: command.Reason, Revision: command.ExpectedRevision + 1, OccurredAt: now}
	receipt := DelegationReceipt{AdministrativeEvent: event, RequestDigest: digest, Command: command, Delegation: delegation}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return DelegationReceipt{}, err
	}
	encoded, err = json.Marshal(receipt)
	if err != nil {
		return DelegationReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, command.SubjectID, key, digest, string(encoded), now); err != nil {
		return DelegationReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return DelegationReceipt{}, err
	}
	return receipt, nil
}

type DelegationRepository interface {
	ChangeDelegation(context.Context, sharedkernel.Scope, DelegationCommand) (DelegationReceipt, error)
}

func (m *Module) delegationChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "delegation.manage", Scope: ManagementScope{Type: "tenant", TenantID: actor.Principal.TenantID}})
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if !decision.Allowed {
		m.permissionError(w, ErrPermissionDenied)
		return
	}
	var command DelegationCommand
	if decode(r, &command) != nil || validateDelegationCommand(command) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/delegations:preview" {
		store, ok := m.store.(DelegationPreviewRepository)
		if !ok {
			m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
			return
		}
		preview, err := store.PreviewDelegation(r.Context(), actor.Scope, command)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, preview)
		return
	}
	store, ok := m.store.(DelegationRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	receipt, err := store.ChangeDelegation(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
