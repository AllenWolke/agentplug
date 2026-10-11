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

type AdministratorCommand struct {
	SubjectID        string          `json:"subject_id"`
	ExpectedRevision uint64          `json:"expected_revision"`
	IdempotencyKey   string          `json:"idempotency_key"`
	Reason           string          `json:"reason"`
	RoleCode         string          `json:"role_code,omitempty"`
	RoleVersion      uint64          `json:"role_version,omitempty"`
	Scope            ManagementScope `json:"scope"`
	Validity
	RevokeBindingIDs []string `json:"revoke_binding_ids,omitempty"`
	StepUpToken      string   `json:"step_up_token,omitempty"`
}

type AdministratorReceipt struct {
	AdministrativeEvent
	RequestDigest string               `json:"request_digest"`
	Command       AdministratorCommand `json:"change"`
	Binding       *RoleBinding         `json:"role_binding,omitempty"`
}

func AdministratorCommandDigest(command AdministratorCommand) (string, error) {
	command.StepUpToken = ""
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	return permissionHash(raw), nil
}

func validateAdministratorCommand(command AdministratorCommand, now time.Time) error {
	if strings.TrimSpace(command.SubjectID) == "" || command.ExpectedRevision == 0 || command.IdempotencyKey == "" || len(command.IdempotencyKey) > 128 || strings.TrimSpace(command.Reason) == "" || len(command.Reason) > 2000 || len(command.RevokeBindingIDs) > 100 || command.Validity.Validate() != nil {
		return ErrInvalidResource
	}
	if command.RoleCode == "" {
		if len(command.RevokeBindingIDs) == 0 {
			return ErrInvalidResource
		}
	} else {
		if command.Scope.Validate() != nil || (command.ExpiresAt != nil && !command.ExpiresAt.After(now)) {
			return ErrInvalidResource
		}
		switch command.RoleCode {
		case "super_admin":
			if command.Scope.Type != "global" || command.RoleVersion > 1 {
				return ErrInvalidResource
			}
		case "permission_admin":
			if command.RoleVersion > 1 || command.Scope.Type != "tenant" && command.Scope.Type != "department" && command.Scope.Type != "application" {
				return ErrInvalidResource
			}
		case "tenant_admin":
			if command.RoleVersion != 2 || command.Scope.Type != "tenant" {
				return ErrInvalidResource
			}
		default:
			return ErrInvalidResource
		}
	}
	seen := map[string]bool{}
	for _, id := range command.RevokeBindingIDs {
		if id == "" || seen[id] {
			return ErrInvalidResource
		}
		seen[id] = true
	}
	return nil
}

func requireSuperAdministrator(snapshot PermissionSnapshot, action string, now time.Time) error {
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: action, Scope: ManagementScope{Type: "global"}, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	for _, b := range snapshot.Bindings {
		if b.RoleCode == "super_admin" && slices.Contains(decision.BindingIDs, b.ID) {
			return nil
		}
	}
	return ErrPermissionDenied
}

func (s *SQLStore) AppointAdministrator(ctx context.Context, actor sharedkernel.Scope, command AdministratorCommand) (AdministratorReceipt, error) {
	if s.administrativeRecorder == nil {
		return AdministratorReceipt{}, ErrPermissionRecorderUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) {
		return AdministratorReceipt{}, ErrInvalidResource
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if err := validateAdministratorCommand(command, now); err != nil {
		return AdministratorReceipt{}, err
	}
	digest, err := AdministratorCommandDigest(command)
	if err != nil {
		return AdministratorReceipt{}, err
	}
	key := permissionHash([]byte("administrator.appoint\x00" + actor.PrincipalID + "\x00" + command.IdempotencyKey))
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return AdministratorReceipt{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return AdministratorReceipt{}, err
	}
	ids := []string{actor.PrincipalID, command.SubjectID}
	slices.Sort(ids)
	for _, id := range slices.Compact(ids) {
		var revision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type='user' AND id=? FOR UPDATE`), id).Scan(&revision); err != nil {
			return AdministratorReceipt{}, err
		}
	}
	now = s.clock().UTC().Truncate(time.Microsecond)
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return AdministratorReceipt{}, err
	}
	if err := requireSuperAdministrator(owner, "administrator.appoint", now); err != nil {
		return AdministratorReceipt{}, err
	}
	var priorDigest string
	var encoded []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_digest,receipt FROM platform_identity_authorization_change WHERE idempotency_hash=?`), key).Scan(&priorDigest, &encoded)
	if err == nil {
		if priorDigest != digest {
			return AdministratorReceipt{}, ErrIdentityConflict
		}
		var receipt AdministratorReceipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return AdministratorReceipt{}, err
	}
	target, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, command.SubjectID)
	if err != nil {
		return AdministratorReceipt{}, err
	}
	if target.Mode != "v2" || !target.Principal.IsActive {
		return AdministratorReceipt{}, ErrPermissionDenied
	}
	if target.Principal.Revision != command.ExpectedRevision {
		return AdministratorReceipt{}, ErrIdentityConflict
	}
	if err := consumeStepUp(ctx, tx, actor, command.StepUpToken, "administrator.appoint", digest, now); err != nil {
		return AdministratorReceipt{}, err
	}
	protect := false
	for _, b := range target.Bindings {
		if b.RoleCode == "super_admin" && b.Status == "active" && b.Effective(now) {
			protect = true
		}
	}
	for _, id := range command.RevokeBindingIDs {
		var binding *RoleBinding
		for i := range target.Bindings {
			if target.Bindings[i].ID == id {
				binding = &target.Bindings[i]
				break
			}
		}
		if binding == nil || binding.Status != "active" || !protectedAdministratorBinding(*binding) {
			return AdministratorReceipt{}, ErrInvalidResource
		}
		binding.Status = "revoked"
		binding.Revision++
		raw, err := json.Marshal(binding)
		if err != nil {
			return AdministratorReceipt{}, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=revision+1,payload=? WHERE id=? AND subject_id=? AND status='active'`), string(raw), id, command.SubjectID); err != nil {
			return AdministratorReceipt{}, err
		}
	}
	var binding *RoleBinding
	if command.RoleCode != "" {
		version := command.RoleVersion
		if version == 0 {
			version = 1
		}
		defined := false
		for _, role := range target.Roles {
			if role.Code == command.RoleCode && role.Version == version && slices.Contains(role.ScopeTypes, command.Scope.Type) {
				defined = true
			}
		}
		if !defined {
			return AdministratorReceipt{}, ErrInvalidResource
		}
		if err := validatePermissionScope(ctx, tx, command.Scope); err != nil {
			return AdministratorReceipt{}, err
		}
		if command.RoleCode == "tenant_admin" && command.Scope.TenantID != target.Principal.TenantID {
			return AdministratorReceipt{}, ErrScopeMismatch
		}
		if command.RoleCode == "permission_admin" {
			if command.Scope.TenantID != target.Principal.TenantID {
				return AdministratorReceipt{}, ErrScopeMismatch
			}
			member := false
			for _, m := range target.Memberships {
				if m.Status == "active" && m.Effective(now) && m.Scope.Contains(command.Scope) {
					member = true
				}
			}
			if !member {
				return AdministratorReceipt{}, ErrPermissionDenied
			}
		}
		var authenticated bool
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT (EXISTS(SELECT 1 FROM platform_identity_local_credential WHERE principal_id=? AND tenant_id=? AND active=TRUE) OR EXISTS(SELECT 1 FROM platform_identity_oidc_binding WHERE principal_id=? AND tenant_id=? AND status='active'))`), command.SubjectID, target.Principal.TenantID, command.SubjectID, target.Principal.TenantID).Scan(&authenticated); err != nil {
			return AdministratorReceipt{}, err
		}
		if !authenticated {
			return AdministratorReceipt{}, ErrPermissionDenied
		}
		binding = &RoleBinding{ID: "administrator-" + key, SubjectID: command.SubjectID, RoleCode: command.RoleCode, RoleVersion: version, Scope: command.Scope, Validity: command.Validity, Status: "active", Revision: 1, SourceID: "appointment-" + key}
		if err := insertRoleBinding(ctx, tx, *binding); err != nil {
			return AdministratorReceipt{}, err
		}
		if command.RoleCode == "super_admin" {
			protect = true
		}
	}
	if protect {
		if err := ensurePermanentAdministrator(ctx, tx, "", "", now); err != nil {
			return AdministratorReceipt{}, err
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='user' AND id=? AND revision=? AND active=TRUE`), command.SubjectID, command.ExpectedRevision)
	if err != nil {
		return AdministratorReceipt{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return AdministratorReceipt{}, err
	}
	if count != 1 {
		return AdministratorReceipt{}, ErrIdentityConflict
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET revision=revision+1,epoch=epoch+1 WHERE principal_type='user' AND subject_id=? AND policy_mode='v2'`), command.SubjectID); err != nil {
		return AdministratorReceipt{}, err
	}
	if err := invalidateAuthorizationStepUp(ctx, tx, PrincipalUser, command.SubjectID); err != nil {
		return AdministratorReceipt{}, err
	}
	command.StepUpToken = ""
	event := AdministrativeEvent{SubjectType: PrincipalUser, ID: "appointment-" + key, ActorID: actor.PrincipalID, SubjectID: command.SubjectID, Action: "administrator.appoint", Reason: command.Reason, Revision: command.ExpectedRevision + 1, OccurredAt: now}
	receipt := AdministratorReceipt{AdministrativeEvent: event, RequestDigest: digest, Command: command, Binding: binding}
	if err := s.administrativeRecorder(ctx, tx, actor, event); err != nil {
		return AdministratorReceipt{}, err
	}
	encoded, err = json.Marshal(receipt)
	if err != nil {
		return AdministratorReceipt{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_authorization_change(id,actor_id,subject_id,idempotency_hash,request_digest,receipt,created_at) VALUES(?,?,?,?,?,?,?)`), event.ID, actor.PrincipalID, command.SubjectID, key, digest, string(encoded), now); err != nil {
		return AdministratorReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdministratorReceipt{}, err
	}
	return receipt, nil
}

type AdministratorRepository interface {
	AppointAdministrator(context.Context, sharedkernel.Scope, AdministratorCommand) (AdministratorReceipt, error)
}

func (m *Module) appointAdministrator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, repo, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	decision, err := repo.ResolvePermission(r.Context(), PrincipalUser, actor.Principal.ID, PermissionQuery{Action: "administrator.appoint", Scope: ManagementScope{Type: "global"}})
	if err != nil {
		m.permissionError(w, err)
		return
	}
	if !decision.Allowed {
		m.permissionError(w, ErrPermissionDenied)
		return
	}
	var command AdministratorCommand
	if decode(r, &command) != nil || validateAdministratorCommand(command, time.Now().UTC()) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/administrators:preview" {
		command.StepUpToken = ""
		digest, err := AdministratorCommandDigest(command)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, map[string]any{"request_digest": digest, "step_up_action": "administrator.appoint", "change": command})
		return
	}
	store, ok := m.store.(AdministratorRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	receipt, err := store.AppointAdministrator(r.Context(), actor.Scope, command)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, receipt)
}
