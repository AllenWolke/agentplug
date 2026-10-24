package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

const RefreshSessionLifetime = 7 * 24 * time.Hour

var ErrRefreshSessionRejected = errors.New("refresh session rejected")

var errRefreshExclusiveRequired = errors.New("refresh changes authentication scope and requires exclusive continuity")

type RefreshSessionResult struct {
	SessionID            string        `json:"session_id"`
	AuthenticationMethod string        `json:"authentication_method"`
	RefreshToken         string        `json:"refresh_token"`
	ExpiresAt            time.Time     `json:"expires_at"`
	Identity             LocalIdentity `json:"identity"`
}

// The opaque bearer value never reaches durable storage. Used hashes remain
// until family expiry so replay can revoke the successor, including after restart.
func refreshSecret() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, refreshHash(token), nil
}
func refreshHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func validRefreshToken(token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(raw) == 32 && len(token) == 43
}

func (s *SQLStore) EnsureRefreshSessionSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_refresh_family (id VARCHAR(64) PRIMARY KEY,principal_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,auth_revision NUMERIC(20,0) CHECK (auth_revision>=0 AND auth_revision<=18446744073709551615) NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL,expires_at TIMESTAMPTZ(6) NOT NULL,revoked BOOLEAN NOT NULL DEFAULT FALSE);
CREATE INDEX IF NOT EXISTS idx_refresh_principal ON platform_identity_refresh_family (principal_id,tenant_id,revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_expiry ON platform_identity_refresh_family (expires_at);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_refresh_token (token_hash VARCHAR(64) PRIMARY KEY,family_id VARCHAR(64) NOT NULL,used BOOLEAN NOT NULL DEFAULT FALSE,created_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_refresh_token_family ON platform_identity_refresh_token (family_id);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_refresh_oidc_binding (family_id VARCHAR(64) PRIMARY KEY,binding_key VARCHAR(64) NOT NULL,binding_revision NUMERIC(20,0) CHECK (binding_revision>=0 AND binding_revision<=18446744073709551615) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_refresh_oidc_key ON platform_identity_refresh_oidc_binding (binding_key);`,
	} {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return err
		}
	}
	return nil
}

// Lock the current authentication facts before creating or rotating a family.
// Refresh renews authentication; it never grants new business permissions.
func loadRefreshIdentity(ctx context.Context, tx *sql.Tx, id string, scope EnrollmentScope, revision uint64) (LocalIdentity, error) {
	return loadRefreshIdentityLocked(ctx, tx, id, scope, revision, true)
}

func loadRefreshIdentityLocked(ctx context.Context, tx *sql.Tx, id string, scope EnrollmentScope, revision uint64, exclusive bool) (LocalIdentity, error) {
	var identity LocalIdentity
	var encoded string
	var credentialActive, principalActive bool
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.principal_id,c.tenant_id,c.department_id,c.application_id,c.display_name,c.auth_revision,c.active,p.roles_json,p.active
		FROM platform_identity_local_credential c
		JOIN platform_identity_principal p ON p.principal_type='user' AND p.id=c.principal_id AND p.tenant_id=c.tenant_id
		JOIN platform_identity_tenant t ON t.id=c.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=c.department_id AND d.tenant_id=c.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=c.application_id AND a.tenant_id=c.tenant_id AND a.department_id=c.department_id AND a.status='active'
		WHERE c.principal_id=? AND c.tenant_id=?`+lock), id, scope.TenantID).
		Scan(&identity.PrincipalID, &identity.TenantID, &identity.DepartmentID, &identity.ApplicationID, &identity.DisplayName, &identity.AuthRevision, &credentialActive, &encoded, &principalActive)
	if errors.Is(err, sql.ErrNoRows) {
		return identity, ErrRefreshSessionRejected
	}
	if err != nil {
		return identity, err
	}
	if !credentialActive || !principalActive || revision == 0 || identity.AuthRevision != revision {
		return LocalIdentity{}, ErrRefreshSessionRejected
	}
	identity.Roles, err = authenticationRoleProjection(ctx, tx, identity.PrincipalID, encoded)
	if err != nil {
		return LocalIdentity{}, err
	}
	identity.Username = identity.PrincipalID
	return identity, nil
}

func (s *SQLStore) CreateRefreshSession(ctx context.Context, id string, scope EnrollmentScope, revision uint64) (RefreshSessionResult, error) {
	if s == nil || s.db == nil || id == "" || !scope.valid() || revision == 0 {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	token, hash, err := refreshSecret()
	if err != nil {
		return RefreshSessionResult{}, err
	}
	_, family, err := refreshSecret()
	if err != nil {
		return RefreshSessionResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	defer tx.Rollback()
	identity, err := loadRefreshIdentity(ctx, tx, id, scope, revision)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	if identity.DepartmentID != scope.DepartmentID || identity.ApplicationID != scope.ApplicationID {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	expires := now.Add(RefreshSessionLifetime)
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_family(id,principal_id,tenant_id,department_id,application_id,auth_revision,created_at,expires_at,revoked) VALUES(?,?,?,?,?,?,?,?,FALSE)`), family, id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, revision, now, expires); err != nil {
		return RefreshSessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_token(token_hash,family_id,used,created_at) VALUES(?,?,FALSE,?)`), hash, family, now); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := s.recordRefreshSession(ctx, tx, family, identity, "created"); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshSessionResult{}, err
	}
	return RefreshSessionResult{SessionID: family, AuthenticationMethod: "local", RefreshToken: token, ExpiresAt: expires, Identity: identity}, nil
}

func (s *SQLStore) RotateRefreshSession(ctx context.Context, token string) (RefreshSessionResult, error) {
	return s.rotateRefreshWorkspace(ctx, token, "", 0, nil)
}

func (s *SQLStore) SwitchRefreshWorkspace(ctx context.Context, token, subject string, revision uint64, target EnrollmentScope) (RefreshSessionResult, error) {
	if subject == "" || revision == 0 || !target.valid() {
		return RefreshSessionResult{}, ErrPermissionDenied
	}
	return s.rotateRefreshWorkspace(ctx, token, subject, revision, &target)
}

func (s *SQLStore) rotateRefreshWorkspace(ctx context.Context, token, subject string, expectedRevision uint64, target *EnrollmentScope) (RefreshSessionResult, error) {
	// Ordinary rotation changes only this family's single-use token. It must
	// not wait for unrelated protected business commits holding IAM shared.
	// Replay revocation and workspace changes still need the exclusive fence.
	// Never upgrade a held shared lock: roll back and reread all facts first.
	result, err := s.rotateRefreshWorkspaceAttempt(ctx, token, subject, expectedRevision, target, target != nil)
	if errors.Is(err, errRefreshExclusiveRequired) {
		return s.rotateRefreshWorkspaceAttempt(ctx, token, subject, expectedRevision, target, true)
	}
	return result, err
}

func (s *SQLStore) rotateRefreshWorkspaceAttempt(ctx context.Context, token, subject string, expectedRevision uint64, target *EnrollmentScope, exclusive bool) (RefreshSessionResult, error) {
	if s == nil || s.db == nil || !validRefreshToken(token) {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	// Resolve immutable family coordinates before locks; writes lock auth facts
	// before family rows, the same order as password/disable transactions.
	var family, id, bindingKey string
	var scope EnrollmentScope
	var revision uint64
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT f.id,f.principal_id,f.tenant_id,f.department_id,f.application_id,f.auth_revision,COALESCE(o.binding_key,'') FROM platform_identity_refresh_token t JOIN platform_identity_refresh_family f ON f.id=t.family_id LEFT JOIN platform_identity_refresh_oidc_binding o ON o.family_id=f.id WHERE t.token_hash=?`), refreshHash(token)).Scan(&family, &id, &scope.TenantID, &scope.DepartmentID, &scope.ApplicationID, &revision, &bindingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	if err != nil {
		return RefreshSessionResult{}, err
	}
	if target != nil && (subject != id || expectedRevision != revision || target.TenantID != scope.TenantID) {
		return RefreshSessionResult{}, ErrPermissionDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return RefreshSessionResult{}, err
	}
	defer tx.Rollback()
	if exclusive {
		err = lockPermissionContinuity(ctx, tx)
	} else {
		err = s.AcquirePermissionReadContinuity(ctx, tx)
	}
	if err != nil {
		return RefreshSessionResult{}, err
	}
	var identity LocalIdentity
	if bindingKey == "" {
		identity, err = loadRefreshIdentityLocked(ctx, tx, id, scope, revision, exclusive)
	} else {
		identity, err = loadOIDCRefreshIdentityLocked(ctx, tx, bindingKey, revision, exclusive)
	}
	if err != nil {
		return RefreshSessionResult{}, err
	}
	var expires time.Time
	var revoked, used bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT expires_at,revoked,department_id,application_id FROM platform_identity_refresh_family WHERE id=? FOR UPDATE`), family).Scan(&expires, &revoked, &scope.DepartmentID, &scope.ApplicationID); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT used FROM platform_identity_refresh_token WHERE token_hash=? AND family_id=? FOR UPDATE`), refreshHash(token), family).Scan(&used); err != nil {
		return RefreshSessionResult{}, err
	}
	now := s.clock().UTC()
	if revoked || !now.Before(expires) {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	if used {
		if !exclusive {
			return RefreshSessionResult{}, errRefreshExclusiveRequired
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family SET revoked=TRUE WHERE id=?`), family); err != nil {
			return RefreshSessionResult{}, err
		}
		if err := s.recordRefreshSession(ctx, tx, family, identity, "replay_revoked"); err != nil {
			return RefreshSessionResult{}, err
		}
		if err := tx.Commit(); err != nil {
			return RefreshSessionResult{}, err
		}
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	if target != nil {
		if err := validateWorkspaceSelection(ctx, tx, id, *target, now); err != nil {
			return RefreshSessionResult{}, err
		}
		scope = *target
	} else if scope.DepartmentID != identity.DepartmentID || scope.ApplicationID != identity.ApplicationID {
		if err := validateWorkspaceSelection(ctx, tx, id, scope, now); err != nil {
			if !errors.Is(err, ErrPermissionDenied) && !errors.Is(err, ErrScopeMismatch) {
				return RefreshSessionResult{}, err
			}
			// Lost membership removes workspace use, without destroying authentication.
			if !exclusive {
				return RefreshSessionResult{}, errRefreshExclusiveRequired
			}
			scope = EnrollmentScope{TenantID: identity.TenantID, DepartmentID: identity.DepartmentID, ApplicationID: identity.ApplicationID}
		}
	}
	identity.DepartmentID, identity.ApplicationID = scope.DepartmentID, scope.ApplicationID
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family SET department_id=?,application_id=? WHERE id=?`), scope.DepartmentID, scope.ApplicationID, family); err != nil {
		return RefreshSessionResult{}, err
	}
	next, hash, err := refreshSecret()
	if err != nil {
		return RefreshSessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_token SET used=TRUE WHERE token_hash=?`), refreshHash(token)); err != nil {
		return RefreshSessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_token(token_hash,family_id,used,created_at) VALUES(?,?,FALSE,?)`), hash, family, now); err != nil {
		return RefreshSessionResult{}, err
	}
	action := "rotated"
	if target != nil {
		action = "workspace_switched"
	}
	if err := s.recordRefreshSession(ctx, tx, family, identity, action); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshSessionResult{}, err
	}
	method := "local"
	if bindingKey != "" {
		method = "oidc"
	}
	return RefreshSessionResult{SessionID: family, AuthenticationMethod: method, RefreshToken: next, ExpiresAt: expires, Identity: identity}, nil
}

func (s *SQLStore) RevokeRefreshSession(ctx context.Context, token string) error {
	if s == nil || s.db == nil || !validRefreshToken(token) {
		return ErrRefreshSessionRejected
	}
	var family string
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT family_id FROM platform_identity_refresh_token WHERE token_hash=?`), refreshHash(token)).Scan(&family); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var identity LocalIdentity
	var revoked bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT principal_id,tenant_id,department_id,application_id,revoked FROM platform_identity_refresh_family WHERE id=? FOR UPDATE`), family).Scan(&identity.PrincipalID, &identity.TenantID, &identity.DepartmentID, &identity.ApplicationID, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if revoked {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family SET revoked=TRUE WHERE id=?`), family); err != nil {
		return err
	}
	if err := s.recordRefreshSession(ctx, tx, family, identity, "revoked"); err != nil {
		return err
	}
	return tx.Commit()
}

func revokePrincipalRefreshSessions(ctx context.Context, tx *sql.Tx, id, tenant string) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family SET revoked=TRUE WHERE principal_id=? AND tenant_id=? AND revoked=FALSE`), id, tenant)
	return err
}

func revokeOIDCRefreshSessions(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_refresh_family f SET revoked=TRUE FROM platform_identity_refresh_oidc_binding o WHERE o.family_id=f.id AND o.binding_key=? AND f.revoked=FALSE`), key)
	return err
}

func loadOIDCRefreshIdentity(ctx context.Context, tx *sql.Tx, key string, revision uint64) (LocalIdentity, error) {
	return loadOIDCRefreshIdentityLocked(ctx, tx, key, revision, true)
}

func loadOIDCRefreshIdentityLocked(ctx context.Context, tx *sql.Tx, key string, revision uint64, exclusive bool) (LocalIdentity, error) {
	var identity LocalIdentity
	var roles string
	var active bool
	var status string
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT b.principal_id,b.tenant_id,b.department_id,b.application_id,b.revision,b.status,p.active,p.roles_json
		FROM platform_identity_oidc_binding b JOIN platform_identity_principal p ON p.principal_type='user' AND p.id=b.principal_id AND p.tenant_id=b.tenant_id
		JOIN platform_identity_tenant t ON t.id=b.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=b.department_id AND d.tenant_id=b.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=b.application_id AND a.department_id=b.department_id AND a.tenant_id=b.tenant_id AND a.status='active'
		WHERE b.identity_key=?`+lock), key).Scan(&identity.PrincipalID, &identity.TenantID, &identity.DepartmentID, &identity.ApplicationID, &identity.AuthRevision, &status, &active, &roles)
	if errors.Is(err, sql.ErrNoRows) {
		return identity, ErrRefreshSessionRejected
	}
	if err != nil {
		return identity, err
	}
	if !active || status != "active" || (revision != 0 && revision != identity.AuthRevision) {
		return identity, ErrRefreshSessionRejected
	}
	identity.Roles, err = authenticationRoleProjection(ctx, tx, identity.PrincipalID, roles)
	if err != nil {
		return LocalIdentity{}, err
	}
	identity.Username = identity.PrincipalID
	identity.DisplayName = identity.PrincipalID
	return identity, nil
}

func (s *SQLStore) CreateOIDCRefreshSession(ctx context.Context, issuer, subject string) (RefreshSessionResult, error) {
	if s == nil || s.db == nil || !validOIDCIdentity(issuer, subject) {
		return RefreshSessionResult{}, ErrRefreshSessionRejected
	}
	token, hash, err := refreshSecret()
	if err != nil {
		return RefreshSessionResult{}, err
	}
	_, family, err := refreshSecret()
	if err != nil {
		return RefreshSessionResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	defer tx.Rollback()
	key := oidcIdentityKey(issuer, subject)
	identity, err := loadOIDCRefreshIdentity(ctx, tx, key, 0)
	if err != nil {
		return RefreshSessionResult{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	expires := now.Add(RefreshSessionLifetime)
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_family(id,principal_id,tenant_id,department_id,application_id,auth_revision,created_at,expires_at,revoked) VALUES(?,?,?,?,?,?,?,?,FALSE)`), family, identity.PrincipalID, identity.TenantID, identity.DepartmentID, identity.ApplicationID, identity.AuthRevision, now, expires); err != nil {
		return RefreshSessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_oidc_binding(family_id,binding_key,binding_revision) VALUES(?,?,?)`), family, key, identity.AuthRevision); err != nil {
		return RefreshSessionResult{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_refresh_token(token_hash,family_id,used,created_at) VALUES(?,?,FALSE,?)`), hash, family, now); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := s.recordRefreshSession(ctx, tx, family, identity, "created"); err != nil {
		return RefreshSessionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshSessionResult{}, err
	}
	return RefreshSessionResult{SessionID: family, AuthenticationMethod: "oidc", RefreshToken: token, ExpiresAt: expires, Identity: identity}, nil
}
