package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type OIDCStepUpRequest struct {
	Scope         sharedkernel.Scope `json:"scope"`
	SessionID     string             `json:"session_id"`
	AuthRevision  uint64             `json:"auth_revision"`
	Action        string             `json:"action"`
	RequestDigest string             `json:"request_digest"`
}

type OIDCStepUpChallenge struct {
	Token     string    `json:"challenge_token"`
	Nonce     string    `json:"nonce"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Only a gateway that verified the provider's signed ID Token may complete a
// challenge. Browser-provided timestamps, identity headers or tokens are not
// authentication evidence for these internal routes.
type OIDCStepUpCompletion struct {
	OIDCStepUpRequest
	ChallengeToken  string    `json:"challenge_token"`
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	Nonce           string    `json:"nonce"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

func (s *SQLStore) EnsureOIDCStepUpSchema(ctx context.Context) error {
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_oidc_step_up_challenge (
		 token_hash VARCHAR(64) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,
		 family_id VARCHAR(64) NOT NULL,auth_revision NUMERIC(20,0) CHECK (auth_revision>=0 AND auth_revision<=18446744073709551615) NOT NULL,action VARCHAR(64) NOT NULL,
		 request_digest VARCHAR(64) NOT NULL,nonce_hash VARCHAR(64) NOT NULL,created_at TIMESTAMPTZ(6) NOT NULL,
		 expires_at TIMESTAMPTZ(6) NOT NULL,used BOOLEAN NOT NULL DEFAULT FALSE);
CREATE INDEX IF NOT EXISTS idx_oidc_step_up_challenge_expiry ON platform_identity_oidc_step_up_challenge (expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_step_up_challenge_subject ON platform_identity_oidc_step_up_challenge (subject_id,tenant_id);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_oidc_step_up_proof (
		 token_hash VARCHAR(64) PRIMARY KEY,family_id VARCHAR(64) NOT NULL,department_id VARCHAR(128) NOT NULL,
		 application_id VARCHAR(128) NOT NULL,binding_key VARCHAR(64) NOT NULL,
		 binding_revision NUMERIC(20,0) CHECK (binding_revision>=0 AND binding_revision<=18446744073709551615) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_oidc_step_up_proof_family ON platform_identity_oidc_step_up_proof (family_id);`,
	} {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(ddl)); err != nil {
			return err
		}
	}
	return nil
}

type oidcStepUpIdentity struct {
	Issuer, Subject, BindingKey string
	Revision                    uint64
}

func validateOIDCStepUpSession(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, session string, revision uint64, now time.Time) (oidcStepUpIdentity, error) {
	var result oidcStepUpIdentity
	if actor.Validate() != nil || actor.PrincipalType != "user" || len(session) != 64 || revision == 0 {
		return result, ErrStepUpRequired
	}
	// Hold authentication rows for update and organization/principal rows for
	// share. Locking the entire join for update would block the tool owner's
	// separate current-IAM read transaction while this proof transaction waits
	// for that read to finish. Shared source locks still prevent hierarchy or
	// principal changes before commit; IAM writers also hold continuity.
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT b.issuer,b.subject,b.identity_key,b.revision FROM platform_identity_refresh_family f
	 JOIN platform_identity_refresh_oidc_binding o ON o.family_id=f.id
	 JOIN platform_identity_oidc_binding b ON b.identity_key=o.binding_key AND b.status='active' AND b.revision=o.binding_revision AND b.revision=f.auth_revision AND b.principal_id=f.principal_id AND b.tenant_id=f.tenant_id
	 JOIN platform_identity_principal p ON p.principal_type='user' AND p.id=f.principal_id AND p.tenant_id=f.tenant_id AND p.active=TRUE
	 JOIN platform_identity_tenant t ON t.id=f.tenant_id AND t.status='active'
	 JOIN platform_identity_department d ON d.id=f.department_id AND d.tenant_id=f.tenant_id AND d.status='active'
	 JOIN platform_identity_application a ON a.id=f.application_id AND a.department_id=f.department_id AND a.tenant_id=f.tenant_id AND a.status='active'
	 JOIN platform_identity_department od ON od.id=b.department_id AND od.tenant_id=b.tenant_id AND od.status='active'
	 JOIN platform_identity_application oa ON oa.id=b.application_id AND oa.department_id=b.department_id AND oa.tenant_id=b.tenant_id AND oa.status='active'
	 WHERE f.id=? AND f.principal_id=? AND f.tenant_id=? AND f.department_id=? AND f.application_id=? AND f.auth_revision=? AND f.revoked=FALSE AND f.expires_at>?
	 AND EXISTS (SELECT 1 FROM platform_identity_refresh_token rt WHERE rt.family_id=f.id AND rt.used=FALSE)
	 FOR UPDATE OF f,b FOR SHARE OF p,t,d,a,od,oa`), session, actor.PrincipalID, actor.TenantID, actor.DepartmentID, actor.ApplicationID, revision, now).Scan(&result.Issuer, &result.Subject, &result.BindingKey, &result.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrStepUpRequired
	}
	if err != nil {
		return result, err
	}
	if err := validateWorkspace(ctx, tx, actor.PrincipalID, EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, now); err != nil {
		return result, err
	}
	return result, nil
}

func authorizeOIDCStepUp(ctx context.Context, tx *sql.Tx, request OIDCStepUpRequest, now time.Time) (oidcStepUpIdentity, error) {
	if !validStepUpBinding(request.Action, request.RequestDigest) {
		return oidcStepUpIdentity{}, ErrInvalidResource
	}
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, request.Scope.PrincipalID)
	if err != nil {
		return oidcStepUpIdentity{}, err
	}
	if owner.Principal.TenantID != request.Scope.TenantID {
		return oidcStepUpIdentity{}, ErrPermissionDenied
	}
	if toolStepUpAction(request.Action) {
		// Business authentication does not require an administrator identity.
		// This proves only fresh authentication for the exact action/digest;
		// the tool owner still checks Run, policy, checkpoint and resource IAM
		// when consuming it inside the approval or revocation transaction.
		if owner.Mode != "v2" {
			return oidcStepUpIdentity{}, ErrPermissionDenied
		}
		member := false
		workspace := ManagementScope{Type: "application", TenantID: request.Scope.TenantID, DepartmentID: request.Scope.DepartmentID, ApplicationID: request.Scope.ApplicationID}
		for _, membership := range owner.Memberships {
			if membership.SubjectID == owner.Principal.ID && membership.Status == "active" && membership.Effective(now) && membership.Scope.Contains(workspace) {
				member = true
				break
			}
		}
		if !member {
			return oidcStepUpIdentity{}, ErrPermissionDenied
		}
	} else if err := requireAdministrativeStepUp(owner, request.Action, request.Scope.TenantID, now); err != nil {
		return oidcStepUpIdentity{}, err
	}
	return validateOIDCStepUpSession(ctx, tx, request.Scope, request.SessionID, request.AuthRevision, now)
}

func (s *SQLStore) CreateOIDCStepUpChallenge(ctx context.Context, request OIDCStepUpRequest) (OIDCStepUpChallenge, error) {
	if request.Scope.Validate() != nil || request.Scope.PrincipalType != "user" || !validStepUpBinding(request.Action, request.RequestDigest) {
		return OIDCStepUpChallenge{}, ErrInvalidResource
	}
	if s.administrativeRecorder == nil {
		return OIDCStepUpChallenge{}, ErrPermissionRecorderUnavailable
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return OIDCStepUpChallenge{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return OIDCStepUpChallenge{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	identity, err := authorizeOIDCStepUp(ctx, tx, request, now)
	if err != nil {
		return OIDCStepUpChallenge{}, err
	}
	token, hash, err := refreshSecret()
	if err != nil {
		return OIDCStepUpChallenge{}, err
	}
	nonce, nonceHash, err := refreshSecret()
	if err != nil {
		return OIDCStepUpChallenge{}, err
	}
	expires := now.Add(StepUpLifetime)
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_step_up_challenge(token_hash,subject_id,tenant_id,family_id,auth_revision,action,request_digest,nonce_hash,created_at,expires_at,used) VALUES(?,?,?,?,?,?,?,?,?,?,FALSE)`), hash, request.Scope.PrincipalID, request.Scope.TenantID, request.SessionID, identity.Revision, request.Action, request.RequestDigest, nonceHash, now, expires); err != nil {
		return OIDCStepUpChallenge{}, err
	}
	if err := s.administrativeRecorder(ctx, tx, request.Scope, AdministrativeEvent{ID: "oidc-step-up-start-" + hash, ActorID: request.Scope.PrincipalID, SubjectID: request.Scope.PrincipalID, Action: "authentication.step_up.started", DetailsDigest: request.RequestDigest, OccurredAt: now}); err != nil {
		return OIDCStepUpChallenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return OIDCStepUpChallenge{}, err
	}
	return OIDCStepUpChallenge{Token: token, Nonce: nonce, Issuer: identity.Issuer, Subject: identity.Subject, StartedAt: now, ExpiresAt: expires}, nil
}

func (s *SQLStore) CompleteOIDCStepUp(ctx context.Context, request OIDCStepUpCompletion) (StepUpProof, error) {
	if request.Scope.Validate() != nil || request.Scope.PrincipalType != "user" || !validStepUpBinding(request.Action, request.RequestDigest) || !validRefreshToken(request.ChallengeToken) || !validRefreshToken(request.Nonce) || !validOIDCIdentity(request.Issuer, request.Subject) {
		return StepUpProof{}, ErrInvalidResource
	}
	if s.administrativeRecorder == nil {
		return StepUpProof{}, ErrPermissionRecorderUnavailable
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return StepUpProof{}, err
	}
	defer tx.Rollback()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return StepUpProof{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	identity, err := authorizeOIDCStepUp(ctx, tx, request.OIDCStepUpRequest, now)
	if err != nil {
		return StepUpProof{}, err
	}
	if identity.Issuer != request.Issuer || identity.Subject != request.Subject {
		return StepUpProof{}, ErrStepUpRequired
	}
	var created, expires time.Time
	var used bool
	var nonceHash string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT created_at,expires_at,used,nonce_hash FROM platform_identity_oidc_step_up_challenge WHERE token_hash=? AND subject_id=? AND tenant_id=? AND family_id=? AND auth_revision=? AND action=? AND request_digest=? FOR UPDATE`), refreshHash(request.ChallengeToken), request.Scope.PrincipalID, request.Scope.TenantID, request.SessionID, request.AuthRevision, request.Action, request.RequestDigest).Scan(&created, &expires, &used, &nonceHash)
	if errors.Is(err, sql.ErrNoRows) {
		return StepUpProof{}, ErrStepUpRequired
	}
	if err != nil {
		return StepUpProof{}, err
	}
	if used || !now.Before(expires) || nonceHash != refreshHash(request.Nonce) || request.AuthenticatedAt.IsZero() || request.AuthenticatedAt.Before(created.Truncate(time.Second)) || request.AuthenticatedAt.After(now.Add(5*time.Second)) || !now.Before(request.AuthenticatedAt.Add(StepUpLifetime)) {
		return StepUpProof{}, ErrStepUpRequired
	}
	if freshExpiry := request.AuthenticatedAt.Add(StepUpLifetime); freshExpiry.Before(expires) {
		expires = freshExpiry
	}
	token, hash, err := refreshSecret()
	if err != nil {
		return StepUpProof{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_step_up(token_hash,subject_id,tenant_id,auth_revision,action,request_digest,expires_at,used) VALUES(?,?,?,?,?,?,?,FALSE)`), hash, request.Scope.PrincipalID, request.Scope.TenantID, identity.Revision, request.Action, request.RequestDigest, expires); err != nil {
		return StepUpProof{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_oidc_step_up_proof(token_hash,family_id,department_id,application_id,binding_key,binding_revision) VALUES(?,?,?,?,?,?)`), hash, request.SessionID, request.Scope.DepartmentID, request.Scope.ApplicationID, identity.BindingKey, identity.Revision); err != nil {
		return StepUpProof{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_oidc_step_up_challenge SET used=TRUE WHERE token_hash=? AND used=FALSE`), refreshHash(request.ChallengeToken)); err != nil {
		return StepUpProof{}, err
	}
	if err := s.administrativeRecorder(ctx, tx, request.Scope, AdministrativeEvent{ID: "step-up-" + hash, ActorID: request.Scope.PrincipalID, SubjectID: request.Scope.PrincipalID, Action: "authentication.step_up", DetailsDigest: request.RequestDigest, OccurredAt: now}); err != nil {
		return StepUpProof{}, err
	}
	if err := tx.Commit(); err != nil {
		return StepUpProof{}, err
	}
	return StepUpProof{Token: token, ExpiresAt: expires}, nil
}

type OIDCStepUpRepository interface {
	CreateOIDCStepUpChallenge(context.Context, OIDCStepUpRequest) (OIDCStepUpChallenge, error)
	CompleteOIDCStepUp(context.Context, OIDCStepUpCompletion) (StepUpProof, error)
}

func (m *Module) oidcStepUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !m.requireAuth(w, r) {
		return
	}
	if r.Header.Get("X-Browser-Module") != "" {
		m.error(w, 403, "FORBIDDEN")
		return
	}
	if r.Method != http.MethodPost {
		m.error(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	store, ok := m.store.(OIDCStepUpRepository)
	if !ok {
		m.error(w, 503, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	if r.URL.Path == "/internal/oidc/step-up:challenge" {
		var request OIDCStepUpRequest
		if decode(r, &request) != nil {
			m.error(w, 400, "INVALID_REQUEST")
			return
		}
		result, err := store.CreateOIDCStepUpChallenge(r.Context(), request)
		if err != nil {
			m.permissionError(w, err)
			return
		}
		m.json(w, 200, result)
		return
	}
	var request OIDCStepUpCompletion
	if decode(r, &request) != nil {
		m.error(w, 400, "INVALID_REQUEST")
		return
	}
	result, err := store.CompleteOIDCStepUp(r.Context(), request)
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, 200, result)
}
