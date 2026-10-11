package identity

// Local credential changes are scoped to the authenticated human principal and
// commit credential rotation, session revocation, audit and outbox atomically.
// 本地凭据修改限定为已认证的人类主体，并原子提交凭据轮换、会话吊销、审计和 Outbox。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var (
	ErrCurrentPasswordInvalid     = errors.New("current local credential is invalid")
	ErrLocalCredentialUnavailable = errors.New("active local credential is unavailable")
	ErrCredentialRecorderRequired = errors.New("credential lifecycle recorder is required")
)

type CredentialLifecycleDecision struct {
	PrincipalID  string
	AuthRevision uint64
	OccurredAt   time.Time
}

// CredentialLifecycleRecorder records the credential change in the same
// transaction as the auth revision update.
// CredentialLifecycleRecorder 在认证版本更新的同一事务中写入审计与集成事件。
type CredentialLifecycleRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, CredentialLifecycleDecision) error

type LocalCredentialLifecycleStore interface {
	ChangeOwnPassword(context.Context, sharedkernel.Scope, string, string) (uint64, error)
}

func (s *SQLStore) SetCredentialLifecycleRecorder(recorder CredentialLifecycleRecorder) {
	if s != nil {
		s.credentialLifecycleRecorder = recorder
	}
}

// ChangeOwnPassword verifies the current secret while holding the credential
// row lock, then rotates the hash and auth revision using a CAS update.
// ChangeOwnPassword 在锁定凭据行期间校验当前密码，再用 CAS 更新密码哈希和认证版本。
func (s *SQLStore) ChangeOwnPassword(ctx context.Context, scope sharedkernel.Scope, currentPassword, newPasswordHash string) (uint64, error) {
	if s == nil || s.db == nil || scope.Validate() != nil || scope.PrincipalType != string(PrincipalUser) ||
		strings.TrimSpace(scope.PrincipalID) == "" || currentPassword == "" || !strings.HasPrefix(newPasswordHash, "$pbkdf2-sha256$") {
		return 0, ErrInvalidPrincipal
	}
	if s.credentialLifecycleRecorder == nil {
		return 0, ErrCredentialRecorderRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin local credential change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return 0, err
	}

	var passwordHash string
	var authRevision uint64
	var credentialActive, principalActive bool
	var credentialDepartment, credentialApplication string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.password_hash,c.auth_revision,c.active,p.active,c.department_id,c.application_id
		FROM platform_identity_local_credential c
		JOIN platform_identity_principal p ON p.principal_type=? AND p.id=c.principal_id AND p.tenant_id=c.tenant_id
		WHERE c.principal_id=? AND c.tenant_id=? FOR UPDATE`), PrincipalUser, scope.PrincipalID, scope.TenantID).
		Scan(&passwordHash, &authRevision, &credentialActive, &principalActive, &credentialDepartment, &credentialApplication)
	if errors.Is(err, sql.ErrNoRows) {
		_ = verifyEnrollmentPassword(dummyEnrollmentPasswordHash, currentPassword)
		return 0, ErrLocalCredentialUnavailable
	}
	if err != nil {
		return 0, fmt.Errorf("load own local credential: %w", err)
	}
	if !credentialActive || !principalActive {
		return 0, ErrLocalCredentialUnavailable
	}
	if scope.DepartmentID != credentialDepartment || scope.ApplicationID != credentialApplication {
		if err := validateWorkspace(ctx, tx, scope.PrincipalID, EnrollmentScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}, s.clock().UTC()); err != nil {
			return 0, err
		}
	}
	if !verifyEnrollmentPassword(passwordHash, currentPassword) {
		return 0, ErrCurrentPasswordInvalid
	}
	if authRevision == ^uint64(0) {
		return 0, errors.New("local credential auth revision exhausted")
	}
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_local_credential
		SET password_hash=?,auth_revision=auth_revision+1,updated_at=?
		WHERE principal_id=? AND tenant_id=? AND department_id=? AND application_id=? AND auth_revision=? AND active=TRUE`), newPasswordHash, now, scope.PrincipalID, scope.TenantID, credentialDepartment, credentialApplication, authRevision)
	if err != nil {
		return 0, fmt.Errorf("rotate local credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read local credential rotation result: %w", err)
	}
	if rows != 1 {
		return 0, ErrIdentityConflict
	}
	revision := authRevision + 1
	if err := revokePrincipalRefreshSessions(ctx, tx, scope.PrincipalID, scope.TenantID); err != nil {
		return 0, fmt.Errorf("revoke refresh sessions: %w", err)
	}
	if err := s.credentialLifecycleRecorder(ctx, tx, scope, CredentialLifecycleDecision{
		PrincipalID: scope.PrincipalID, AuthRevision: revision, OccurredAt: now,
	}); err != nil {
		return 0, fmt.Errorf("record local credential change: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit local credential change: %w", err)
	}
	return revision, nil
}

type changeOwnPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (m *Module) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !m.requireAuth(w, r) {
		return
	}
	if r.URL.Path != "/credentials:change-password" || r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.loadBrowserActor(w, r)
	if !ok {
		return
	}
	if !actor.Browser || actor.Principal.Type != PrincipalUser {
		m.error(w, http.StatusForbidden, "BROWSER_HUMAN_IDENTITY_REQUIRED")
		return
	}
	scope, err := identityScopeFromRequest(r)
	if err != nil || scope.PrincipalID != actor.Principal.ID || scope.TenantID != actor.Principal.TenantID {
		m.error(w, http.StatusForbidden, "SELF_CREDENTIAL_SCOPE_REQUIRED")
		return
	}
	var request changeOwnPasswordRequest
	if decode(r, &request) != nil || request.CurrentPassword == "" || len(request.NewPassword) < 10 || len(request.NewPassword) > 128 || request.CurrentPassword == request.NewPassword {
		m.error(w, http.StatusBadRequest, "INVALID_PASSWORD_CHANGE")
		return
	}
	store, ok := m.store.(LocalCredentialLifecycleStore)
	if !ok {
		m.error(w, http.StatusNotImplemented, "LOCAL_CREDENTIAL_CHANGE_UNAVAILABLE")
		return
	}
	hash, err := hashEnrollmentPassword(request.NewPassword)
	if err != nil {
		m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		return
	}
	revision, err := store.ChangeOwnPassword(r.Context(), scope, request.CurrentPassword, hash)
	if err != nil {
		switch {
		case errors.Is(err, ErrCurrentPasswordInvalid), errors.Is(err, ErrLocalCredentialUnavailable):
			m.error(w, http.StatusUnauthorized, "CREDENTIAL_CHANGE_REJECTED")
		case errors.Is(err, ErrCredentialRecorderRequired):
			m.error(w, http.StatusServiceUnavailable, "CREDENTIAL_AUDIT_UNAVAILABLE")
		case errors.Is(err, ErrIdentityConflict):
			m.error(w, http.StatusConflict, "CREDENTIAL_REVISION_CONFLICT")
		default:
			m.error(w, http.StatusInternalServerError, "INTERNAL_ERROR")
		}
		return
	}
	m.json(w, http.StatusOK, map[string]any{"auth_revision": revision, "reauthentication_required": true})
}

var _ LocalCredentialLifecycleStore = (*SQLStore)(nil)
