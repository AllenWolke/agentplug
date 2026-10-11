package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// An OIDC binding is provisioned by a trusted identity administrator. The
// issuer and subject are never inferred from browser-supplied organization or
// role headers. Revocation is immediate because every request reads SQL.
type OIDCIdentity struct {
	Username       string   `json:"username"`
	DisplayName    string   `json:"display_name"`
	TenantID       string   `json:"tenant_id"`
	DepartmentID   string   `json:"department_id"`
	DepartmentName string   `json:"department_name"`
	ApplicationID  string   `json:"application_id"`
	Roles          []string `json:"roles"`
}

type OIDCBindingResolver interface {
	ResolveOIDC(context.Context, string, string) (OIDCIdentity, error)
}

type OIDCBindingManager interface {
	CreateOIDCBinding(context.Context, sharedkernel.Scope, OIDCBinding) error
	DisableOIDCBinding(context.Context, sharedkernel.Scope, OIDCBinding, uint64) error
}

var ErrOIDCBindingRecorderUnavailable = errors.New("OIDC binding recorder is required")

type OIDCBindingDecision struct {
	IdentityKey   string
	TenantID      string
	DepartmentID  string
	ApplicationID string
	PrincipalID   string
	Status        string
	Revision      uint64
	OccurredAt    time.Time
}

// The recorder writes audit/outbox facts through the exact binding transaction.
type OIDCBindingRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, OIDCBindingDecision) error

func (s *SQLStore) SetOIDCBindingRecorder(recorder OIDCBindingRecorder) {
	if s != nil {
		s.oidcBindingRecorder = recorder
	}
}

type OIDCBinding struct {
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	PrincipalID   string `json:"principal_id"`
	TenantID      string `json:"tenant_id"`
	DepartmentID  string `json:"department_id"`
	ApplicationID string `json:"application_id"`
	Status        string `json:"status"`
	Revision      uint64 `json:"revision"`
}

var ErrOIDCBindingNotFound = errors.New("active OIDC binding not found")

const oidcBindingDDL = `CREATE TABLE IF NOT EXISTS platform_identity_oidc_binding (
	identity_key VARCHAR(64) PRIMARY KEY, issuer VARCHAR(512) NOT NULL, subject VARCHAR(512) NOT NULL,
	principal_id VARCHAR(128) NOT NULL, tenant_id VARCHAR(128) NOT NULL,
	department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
	status VARCHAR(32) NOT NULL, created_at TIMESTAMPTZ(6) NOT NULL,
	revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_identity_oidc_principal ON platform_identity_oidc_binding (principal_id,tenant_id);`

func validOIDCIdentity(issuer, subject string) bool {
	u, err := url.Parse(issuer)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && len(issuer) <= 512 && subject != "" && len(subject) <= 512 && !strings.ContainsAny(subject, "\x00\r\n")
}

func oidcIdentityKey(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return hex.EncodeToString(sum[:])
}

// EnsureOIDCBindingSchema is also called when upgrading an existing database.
func (s *SQLStore) EnsureOIDCBindingSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(oidcBindingDDL))
	return err
}

func (s *SQLStore) CreateOIDCBinding(ctx context.Context, actor sharedkernel.Scope, binding OIDCBinding) error {
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || !validOIDCIdentity(binding.Issuer, binding.Subject) || binding.PrincipalID == "" || binding.TenantID == "" || binding.DepartmentID == "" || binding.ApplicationID == "" {
		return ErrInvalidResource
	}
	if s.oidcBindingRecorder == nil {
		return ErrOIDCBindingRecorderUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OIDC binding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_binding(identity_key,issuer,subject,principal_id,tenant_id,department_id,application_id,status,created_at,revision,updated_at)
		SELECT ?,?,?,?,?,?,?,'active',?,1,?
		FROM platform_identity_principal p
		JOIN platform_identity_tenant t ON t.id=p.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=? AND d.tenant_id=p.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=? AND a.department_id=d.id AND a.tenant_id=p.tenant_id AND a.status='active'
		WHERE p.principal_type='user' AND p.id=? AND p.tenant_id=? AND p.active=TRUE`), oidcIdentityKey(binding.Issuer, binding.Subject), binding.Issuer, binding.Subject, binding.PrincipalID,
		binding.TenantID, binding.DepartmentID, binding.ApplicationID, now, now, binding.DepartmentID, binding.ApplicationID,
		binding.PrincipalID, binding.TenantID)
	if err != nil {
		return identityPersistenceError("create OIDC binding", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrOIDCBindingNotFound
	}
	if err := s.oidcBindingRecorder(ctx, tx, actor, OIDCBindingDecision{
		IdentityKey: oidcIdentityKey(binding.Issuer, binding.Subject), TenantID: binding.TenantID,
		DepartmentID: binding.DepartmentID, ApplicationID: binding.ApplicationID, PrincipalID: binding.PrincipalID,
		Status: "active", Revision: 1, OccurredAt: now,
	}); err != nil {
		return fmt.Errorf("record OIDC binding creation: %w", err)
	}
	return tx.Commit()
}

func (s *SQLStore) DisableOIDCBinding(ctx context.Context, actor sharedkernel.Scope, binding OIDCBinding, expectedRevision uint64) error {
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || !validOIDCIdentity(binding.Issuer, binding.Subject) || binding.TenantID == "" || expectedRevision == 0 {
		return ErrInvalidResource
	}
	if s.oidcBindingRecorder == nil {
		return ErrOIDCBindingRecorderUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OIDC binding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return err
	}
	var decision OIDCBindingDecision
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,principal_id FROM platform_identity_oidc_binding
		WHERE identity_key=? AND issuer=? AND subject=? AND tenant_id=? AND status='active' AND revision=? FOR UPDATE`), oidcIdentityKey(binding.Issuer, binding.Subject), binding.Issuer, binding.Subject, binding.TenantID, expectedRevision).
		Scan(&decision.TenantID, &decision.DepartmentID, &decision.ApplicationID, &decision.PrincipalID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIdentityConflict
	}
	if err != nil {
		return fmt.Errorf("load OIDC binding: %w", err)
	}
	if err := protectPermissionAdministrator(ctx, tx, decision.PrincipalID, "", oidcIdentityKey(binding.Issuer, binding.Subject), s.clock().UTC()); err != nil {
		return err
	}
	now := s.clock().UTC()
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_oidc_binding SET status='disabled',revision=revision+1,updated_at=?
		WHERE identity_key=? AND issuer=? AND subject=? AND tenant_id=? AND status='active' AND revision=?`), now, oidcIdentityKey(binding.Issuer, binding.Subject), binding.Issuer, binding.Subject, binding.TenantID, expectedRevision)
	if err != nil {
		return fmt.Errorf("disable OIDC binding: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrIdentityConflict
	}
	decision.IdentityKey, decision.Status, decision.Revision, decision.OccurredAt = oidcIdentityKey(binding.Issuer, binding.Subject), "disabled", expectedRevision+1, now
	if err := revokeOIDCRefreshSessions(ctx, tx, decision.IdentityKey); err != nil {
		return err
	}
	if err := s.oidcBindingRecorder(ctx, tx, actor, decision); err != nil {
		return fmt.Errorf("record OIDC binding revocation: %w", err)
	}
	return tx.Commit()
}

func (s *SQLStore) ResolveOIDC(ctx context.Context, issuer, subject string) (OIDCIdentity, error) {
	if !validOIDCIdentity(issuer, subject) {
		return OIDCIdentity{}, ErrOIDCBindingNotFound
	}
	var result OIDCIdentity
	var rolesJSON string
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT p.id,p.id,b.tenant_id,b.department_id,d.name,b.application_id,p.roles_json
		FROM platform_identity_oidc_binding b
		JOIN platform_identity_principal p ON p.principal_type='user' AND p.id=b.principal_id AND p.tenant_id=b.tenant_id AND p.active=TRUE
		JOIN platform_identity_tenant t ON t.id=b.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=b.department_id AND d.tenant_id=b.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=b.application_id AND a.tenant_id=b.tenant_id AND a.department_id=b.department_id AND a.status='active'
		WHERE b.identity_key=? AND b.issuer=? AND b.subject=? AND b.status='active'`), oidcIdentityKey(issuer, subject), issuer, subject).
		Scan(&result.Username, &result.DisplayName, &result.TenantID, &result.DepartmentID, &result.DepartmentName, &result.ApplicationID, &rolesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return OIDCIdentity{}, ErrOIDCBindingNotFound
	}
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("resolve OIDC binding: %w", err)
	}
	result.Roles, err = authenticationRoleProjection(ctx, s.db, result.Username, rolesJSON)
	if err != nil {
		return OIDCIdentity{}, err
	}
	return result, nil
}

func (m *Module) resolveOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	provided := r.Header.Get("X-Internal-Token")
	if m.internalToken == "" || len(provided) != len(m.internalToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(m.internalToken)) != 1 {
		m.error(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	resolver, ok := m.store.(OIDCBindingResolver)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "OIDC_RESOLVER_UNAVAILABLE")
		return
	}
	var request struct {
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
	}
	if decode(r, &request) != nil || !validOIDCIdentity(request.Issuer, request.Subject) {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	identity, err := resolver.ResolveOIDC(r.Context(), request.Issuer, request.Subject)
	if err != nil {
		if errors.Is(err, ErrOIDCBindingNotFound) {
			m.error(w, http.StatusUnauthorized, "OIDC_BINDING_REJECTED")
		} else {
			m.error(w, http.StatusServiceUnavailable, "OIDC_RESOLVER_UNAVAILABLE")
		}
		return
	}
	m.json(w, http.StatusOK, identity)
}

func (m *Module) oidcBindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !ok {
		return
	}
	manager, ok := m.store.(OIDCBindingManager)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "OIDC_BINDING_MANAGER_UNAVAILABLE")
		return
	}
	var binding OIDCBinding
	if decode(r, &binding) != nil || !validOIDCIdentity(binding.Issuer, binding.Subject) ||
		binding.PrincipalID == "" || binding.TenantID == "" || binding.DepartmentID == "" || binding.ApplicationID == "" || binding.Status != "" || binding.Revision != 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !actor.canManage(binding.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	principal, err := m.store.GetPrincipal(r.Context(), PrincipalUser, binding.PrincipalID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	if !principal.IsActive || principal.TenantID != binding.TenantID {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	if actor.Browser && !containsIdentityRole(actor.Principal.Roles, "system_admin", "admin") && containsIdentityRole(principal.Roles, "system_admin", "admin") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	actorScope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if err := manager.CreateOIDCBinding(r.Context(), actorScope, binding); err != nil {
		m.storeError(w, err)
		return
	}
	binding.Status, binding.Revision = "active", 1
	m.json(w, http.StatusCreated, binding)
}

func (m *Module) disableOIDCBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, ok := m.requireBrowserRoles(w, r, "system_admin", "admin", "platform_admin")
	if !ok {
		return
	}
	manager, ok := m.store.(OIDCBindingManager)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "OIDC_BINDING_MANAGER_UNAVAILABLE")
		return
	}
	var command struct {
		Issuer           string `json:"issuer"`
		Subject          string `json:"subject"`
		TenantID         string `json:"tenant_id"`
		ExpectedRevision uint64 `json:"expected_revision"`
	}
	if decode(r, &command) != nil || !validOIDCIdentity(command.Issuer, command.Subject) || command.TenantID == "" || command.ExpectedRevision == 0 {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	if !actor.canManage(command.TenantID, "", "") {
		m.error(w, http.StatusForbidden, "FORBIDDEN")
		return
	}
	actorScope, err := identityScopeFromRequest(r)
	if err != nil {
		m.error(w, http.StatusBadRequest, "INVALID_SCOPE")
		return
	}
	if err := manager.DisableOIDCBinding(r.Context(), actorScope, OIDCBinding{Issuer: command.Issuer, Subject: command.Subject, TenantID: command.TenantID}, command.ExpectedRevision); err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, map[string]any{"status": "disabled", "revision": command.ExpectedRevision + 1})
}
