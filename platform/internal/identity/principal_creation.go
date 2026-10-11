package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Password is never included in a plan, receipt, audit event or request digest.
// A retry checks the salted credential instead of storing a password fingerprint.
type PrincipalCreationCommand struct {
	Username    string          `json:"username"`
	DisplayName string          `json:"display_name"`
	Password    string          `json:"password,omitempty"`
	Scope       ManagementScope `json:"scope"`
	Validity
	Preset         *PresetSelection `json:"preset,omitempty"`
	IdempotencyKey string           `json:"idempotency_key"`
	Reason         string           `json:"reason"`
	PlanDigest     string           `json:"plan_digest,omitempty"`
	PlanExpiresAt  time.Time        `json:"plan_expires_at,omitempty"`
}

func creationAuthorization(c PrincipalCreationCommand) (AuthorizationChangeCommand, string, error) {
	if !enrollmentUsernamePattern.MatchString(c.Username) || strings.TrimSpace(c.DisplayName) != c.DisplayName || len([]rune(c.DisplayName)) < 2 || len([]rune(c.DisplayName)) > 128 || c.Scope.Type != "application" || c.Scope.Validate() != nil || c.Validity.Validate() != nil || strings.TrimSpace(c.Reason) == "" || len(c.Reason) > 1000 || c.IdempotencyKey == "" || len(c.IdempotencyKey) > 128 {
		return AuthorizationChangeCommand{}, "", ErrInvalidResource
	}
	if c.Preset != nil && !c.Scope.Contains(c.Preset.Scope) {
		return AuthorizationChangeCommand{}, "", ErrScopeMismatch
	}
	c.Password, c.PlanDigest, c.PlanExpiresAt = "", "", time.Time{}
	raw, err := json.Marshal(c)
	if err != nil {
		return AuthorizationChangeCommand{}, "", err
	}
	return AuthorizationChangeCommand{SubjectType: PrincipalUser, SubjectID: c.Username, ExpectedRevision: 1, IdempotencyKey: c.IdempotencyKey, Reason: c.Reason, Preset: c.Preset, Memberships: []MembershipMutation{{ID: "member-" + permissionHash([]byte(c.Username+"\x00"+c.IdempotencyKey)), Scope: c.Scope, Status: "active", Validity: c.Validity}}}, permissionHash(raw), nil
}

func (s *SQLStore) PreviewPrincipalCreation(ctx context.Context, actor sharedkernel.Scope, c PrincipalCreationCommand) (AuthorizationChangePlan, error) {
	command, digest, err := creationAuthorization(c)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_principal WHERE principal_type='user' AND id=?`), c.Username).Scan(&count); err != nil {
		return AuthorizationChangePlan{}, err
	}
	if count != 0 {
		return AuthorizationChangePlan{}, ErrIdentityConflict
	}
	// Preview performs no writes, including temporary credential/account inserts.
	target := PermissionSnapshot{Principal: Principal{Type: PrincipalUser, ID: c.Username, TenantID: c.Scope.TenantID, IsActive: true, Revision: 1, Roles: []string{}, Groups: []string{}}, Mode: "v2", Memberships: []Membership{}, Bindings: []RoleBinding{}, Grants: []Grant{}, Delegations: []Delegation{}}
	plan, err := s.planAuthorizationChangeTarget(ctx, tx, actor, command, s.clock().UTC().Add(5*time.Minute), &target)
	if err != nil {
		return AuthorizationChangePlan{}, err
	}
	plan.Digest = permissionHash([]byte(plan.Digest + "\x00" + digest))
	return plan, tx.Commit()
}

func (s *SQLStore) CreatePermissionPrincipal(ctx context.Context, actor sharedkernel.Scope, c PrincipalCreationCommand) (AuthorizationChangeReceipt, error) {
	if s == nil || s.db == nil || s.authorizationChangeRecorder == nil {
		return AuthorizationChangeReceipt{}, ErrPermissionRecorderUnavailable
	}
	command, digest, err := creationAuthorization(c)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || len(c.Password) < 10 || len(c.Password) > 128 {
		return AuthorizationChangeReceipt{}, ErrInvalidResource
	}
	// Expensive password derivation happens before taking the global IAM guard.
	passwordHash, err := hashEnrollmentPassword(c.Password)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	key := permissionHash([]byte("principal.create\x00" + actor.PrincipalID + "\x00" + c.IdempotencyKey))
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
		if priorDigest != digest {
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
		if err := authorizeReceiptRead(ctx, tx, owner, receipt, s.clock().UTC()); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		var stored string
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT password_hash FROM platform_identity_local_credential WHERE principal_id=? AND active=TRUE`), c.Username).Scan(&stored); err != nil {
			return AuthorizationChangeReceipt{}, err
		}
		if !verifyEnrollmentPassword(stored, c.Password) {
			return AuthorizationChangeReceipt{}, ErrIdentityConflict
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
	now := s.clock().UTC()
	if err := insertPermissionPrincipalTx(ctx, tx, c, passwordHash, now); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	command.PlanDigest, command.PlanExpiresAt = c.PlanDigest, c.PlanExpiresAt
	plan, err := s.planAuthorizationChange(ctx, tx, actor, command, c.PlanExpiresAt)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if c.PlanDigest == "" || c.PlanDigest != permissionHash([]byte(plan.Digest+"\x00"+digest)) {
		return AuthorizationChangeReceipt{}, ErrPermissionPlanStale
	}
	command.PlanDigest = plan.Digest
	receipt, err := s.commitAuthorizationChangeTx(ctx, tx, actor, command, key, digest)
	if err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthorizationChangeReceipt{}, err
	}
	return receipt, nil
}

func insertPermissionPrincipalTx(ctx context.Context, tx *sql.Tx, c PrincipalCreationCommand, passwordHash string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES(?,'user',?,'[]','[]',TRUE,1,?)`), c.Username, c.Scope.TenantID, now); err != nil {
		return identityPersistenceError("create permission principal", err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), c.Username); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,TRUE,?,?)`), c.Username, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID, c.DisplayName, passwordHash, now, now); err != nil {
		return err
	}
	return nil
}

type permissionPrincipalCreator interface {
	PreviewPrincipalCreation(context.Context, sharedkernel.Scope, PrincipalCreationCommand) (AuthorizationChangePlan, error)
	CreatePermissionPrincipal(context.Context, sharedkernel.Scope, PrincipalCreationCommand) (AuthorizationChangeReceipt, error)
}

func (m *Module) permissionPrincipalCreation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(permissionPrincipalCreator)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	var c PrincipalCreationCommand
	if decode(r, &c) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if r.URL.Path == "/principals:preview" {
		plan, err := repo.PreviewPrincipalCreation(r.Context(), actor.Scope, c)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, http.StatusOK, plan)
		return
	}
	receipt, err := repo.CreatePermissionPrincipal(r.Context(), actor.Scope, c)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusCreated, receipt)
}
