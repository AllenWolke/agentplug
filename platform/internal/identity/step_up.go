package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var ErrStepUpRequired = errors.New("fresh action-bound authentication is required")

const StepUpLifetime = 5 * time.Minute

type StepUpRequest struct {
	CurrentPassword string `json:"current_password"`
	Action          string `json:"action"`
	RequestDigest   string `json:"request_digest"`
}

type StepUpProof struct {
	Token     string    `json:"step_up_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AdministrativeEvent struct {
	// Set only for changes that invalidate this principal's authorization.
	SubjectType   PrincipalType `json:"subject_type,omitempty"`
	DetailsDigest string        `json:"details_digest,omitempty"`
	ID            string        `json:"id"`
	ActorID       string        `json:"actor_id"`
	SubjectID     string        `json:"subject_id"`
	Action        string        `json:"action"`
	Reason        string        `json:"reason,omitempty"`
	Revision      uint64        `json:"revision,omitempty"`
	OccurredAt    time.Time     `json:"occurred_at"`
}

type AdministrativeRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error

func (s *SQLStore) SetAdministrativeRecorder(recorder AdministrativeRecorder) {
	s.administrativeRecorder = recorder
}

func (s *SQLStore) EnsureStepUpSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_identity_step_up (
		token_hash VARCHAR(64) PRIMARY KEY,subject_id VARCHAR(128) NOT NULL,tenant_id VARCHAR(128) NOT NULL,
		auth_revision NUMERIC(20,0) CHECK (auth_revision>=0 AND auth_revision<=18446744073709551615) NOT NULL,action VARCHAR(64) NOT NULL,request_digest VARCHAR(64) NOT NULL,
		expires_at TIMESTAMPTZ(6) NOT NULL,used BOOLEAN NOT NULL DEFAULT FALSE);
CREATE INDEX IF NOT EXISTS idx_step_up_expiry ON platform_identity_step_up (expires_at);
CREATE INDEX IF NOT EXISTS idx_step_up_subject ON platform_identity_step_up (subject_id,tenant_id);`))
	return err
}

func validStepUpBinding(action, digest string) bool {
	raw, err := hex.DecodeString(digest)
	return err == nil && len(raw) == 32 && (action == "administrator.appoint" || action == "delegation.manage" || toolStepUpAction(action))
}

func toolStepUpAction(action string) bool {
	return action == "tool.approval.approve" || action == "tool.approval.revoke"
}

// Authorization writers call this under the continuity lock, in the same
// transaction as the changed IAM facts and their audit. A credential revision
// alone cannot detect membership, role or delegation changes. Keep the proof
// metadata until normal expiry cleanup, but reject both issued proofs and
// unfinished OIDC challenges after a committed authorization change.
func invalidateAuthorizationStepUp(ctx context.Context, tx *sql.Tx, kind PrincipalType, subjectID string) error {
	if kind != PrincipalUser {
		return nil
	}
	for _, query := range []string{
		`UPDATE platform_identity_step_up SET used=TRUE WHERE subject_id=? AND used=FALSE`,
		`UPDATE platform_identity_oidc_step_up_challenge SET used=TRUE WHERE subject_id=? AND used=FALSE`,
	} {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(query), subjectID); err != nil {
			return err
		}
	}
	return nil
}

// Root control-plane wiring supplies current session, owner and published
// tool/resource authorization. A password proof never grants those permissions.
type ToolStepUpAuthorization func(context.Context, *sql.Tx, sharedkernel.Scope, string, string) error

func (s *SQLStore) CreateToolStepUp(ctx context.Context, actor sharedkernel.Scope, request StepUpRequest, authorize ToolStepUpAuthorization) (StepUpProof, error) {
	if !toolStepUpAction(request.Action) || authorize == nil {
		return StepUpProof{}, ErrInvalidResource
	}
	return s.createLocalStepUp(ctx, actor, request, func(tx *sql.Tx) error {
		if err := s.validateToolStepUpSubject(ctx, tx, actor); err != nil {
			return err
		}
		return authorize(ctx, tx, actor, request.Action, request.RequestDigest)
	})
}

// The approval owner consumes this inside its approval/audit/Outbox transaction.
// Its root authorizer remains responsible for current resource/run/session IAM.
func (s *SQLStore) ConsumeToolStepUpTx(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, sessionID string, authRevision uint64, token, action, digest string) error {
	if tx == nil || actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || !toolStepUpAction(action) || len(sessionID) != 64 || authRevision == 0 {
		return ErrStepUpRequired
	}
	if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	if err := s.validateToolStepUpSubject(ctx, tx, actor); err != nil {
		return err
	}
	// A valid proof from another still-active login by the same user is not
	// evidence for this request's session. The root supplies these identifiers
	// from its trusted gateway binding, never from the submitted tool command.
	var family string
	var revision uint64
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT family_id,binding_revision FROM platform_identity_oidc_step_up_proof WHERE token_hash=?`), refreshHash(token)).Scan(&family, &revision)
	if err == nil {
		if family != sessionID || revision != authRevision {
			return ErrStepUpRequired
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return consumeStepUp(ctx, tx, actor, token, action, digest, s.clock().UTC())
}

func (s *SQLStore) validateToolStepUpSubject(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope) error {
	snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	if !snapshot.Principal.IsActive || snapshot.Principal.TenantID != actor.TenantID {
		return ErrPermissionDenied
	}
	return validateWorkspace(ctx, tx, actor.PrincipalID, EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, s.clock().UTC())
}

// A proof is short-lived, single-use and bound to the exact administrative
// command. Authentication timestamps supplied by the browser are never trusted.
func (s *SQLStore) CreateLocalStepUp(ctx context.Context, actor sharedkernel.Scope, request StepUpRequest) (StepUpProof, error) {
	if request.Action != "administrator.appoint" && request.Action != "delegation.manage" {
		return StepUpProof{}, ErrInvalidResource
	}
	return s.createLocalStepUp(ctx, actor, request, func(tx *sql.Tx) error {
		snapshot, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			return err
		}
		return requireAdministrativeStepUp(snapshot, request.Action, actor.TenantID, s.clock().UTC())
	})
}

func (s *SQLStore) createLocalStepUp(ctx context.Context, actor sharedkernel.Scope, request StepUpRequest, authorize func(*sql.Tx) error) (StepUpProof, error) {
	if actor.Validate() != nil || actor.PrincipalType != string(PrincipalUser) || request.CurrentPassword == "" || !validStepUpBinding(request.Action, request.RequestDigest) {
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
	if err := s.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return StepUpProof{}, err
	}
	if authorize == nil {
		return StepUpProof{}, ErrPermissionDenied
	}
	if err := authorize(tx); err != nil {
		return StepUpProof{}, err
	}
	var passwordHash string
	var revision uint64
	var active bool
	var credentialDepartment, credentialApplication string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT password_hash,auth_revision,active,department_id,application_id FROM platform_identity_local_credential WHERE principal_id=? AND tenant_id=? FOR UPDATE`), actor.PrincipalID, actor.TenantID).Scan(&passwordHash, &revision, &active, &credentialDepartment, &credentialApplication)
	if errors.Is(err, sql.ErrNoRows) {
		_ = verifyEnrollmentPassword(dummyEnrollmentPasswordHash, request.CurrentPassword)
		return StepUpProof{}, ErrCurrentPasswordInvalid
	}
	if err != nil {
		return StepUpProof{}, err
	}
	if !active || !verifyEnrollmentPassword(passwordHash, request.CurrentPassword) {
		return StepUpProof{}, ErrCurrentPasswordInvalid
	}
	if actor.DepartmentID != credentialDepartment || actor.ApplicationID != credentialApplication {
		if err := validateWorkspace(ctx, tx, actor.PrincipalID, EnrollmentScope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, s.clock().UTC()); err != nil {
			return StepUpProof{}, err
		}
	}
	token, hash, err := refreshSecret()
	if err != nil {
		return StepUpProof{}, err
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	expires := now.Add(StepUpLifetime)
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_step_up(token_hash,subject_id,tenant_id,auth_revision,action,request_digest,expires_at,used) VALUES(?,?,?,?,?,?,?,FALSE)`), hash, actor.PrincipalID, actor.TenantID, revision, request.Action, request.RequestDigest, expires); err != nil {
		return StepUpProof{}, err
	}
	if err := s.administrativeRecorder(ctx, tx, actor, AdministrativeEvent{ID: "step-up-" + hash, ActorID: actor.PrincipalID, SubjectID: actor.PrincipalID, Action: "authentication.step_up", OccurredAt: now}); err != nil {
		return StepUpProof{}, err
	}
	if err := tx.Commit(); err != nil {
		return StepUpProof{}, err
	}
	return StepUpProof{Token: token, ExpiresAt: expires}, nil
}

// Consume within the authorization transaction, after the common continuity
// lock. Failed authorization or audit rolls consumption back with the change.
func consumeStepUp(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, token, action, digest string, now time.Time) error {
	if len(token) != 43 || !validStepUpBinding(action, digest) {
		return ErrStepUpRequired
	}
	var revision uint64
	var expires time.Time
	var used bool
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT auth_revision,expires_at,used FROM platform_identity_step_up WHERE token_hash=? AND subject_id=? AND tenant_id=? AND action=? AND request_digest=? FOR UPDATE`), refreshHash(token), actor.PrincipalID, actor.TenantID, action, digest).Scan(&revision, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStepUpRequired
	}
	if err != nil {
		return err
	}
	if used || !now.Before(expires) {
		return ErrStepUpRequired
	}
	var family, department, application, bindingKey string
	var bindingRevision uint64
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT family_id,department_id,application_id,binding_key,binding_revision FROM platform_identity_oidc_step_up_proof WHERE token_hash=?`), refreshHash(token)).Scan(&family, &department, &application, &bindingKey, &bindingRevision)
	if err == nil {
		if actor.DepartmentID != department || actor.ApplicationID != application || revision != bindingRevision {
			return ErrStepUpRequired
		}
		identity, err := validateOIDCStepUpSession(ctx, tx, actor, family, revision, now)
		if err != nil {
			return err
		}
		if identity.BindingKey != bindingKey || identity.Revision != bindingRevision {
			return ErrStepUpRequired
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		var currentRevision uint64
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT auth_revision FROM platform_identity_local_credential WHERE principal_id=? AND tenant_id=? AND active=TRUE FOR UPDATE`), actor.PrincipalID, actor.TenantID).Scan(&currentRevision); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrStepUpRequired
			}
			return err
		}
		if revision != currentRevision {
			return ErrStepUpRequired
		}
	} else {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_step_up SET used=TRUE WHERE token_hash=? AND used=FALSE`), refreshHash(token))
	return err
}

type StepUpRepository interface {
	CreateLocalStepUp(context.Context, sharedkernel.Scope, StepUpRequest) (StepUpProof, error)
}

func (m *Module) stepUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	actor, _, ok := m.permissionActor(w, r)
	if !ok {
		return
	}
	repo, ok := m.store.(StepUpRepository)
	if !ok {
		m.error(w, http.StatusServiceUnavailable, "PERMISSION_SERVICE_UNAVAILABLE")
		return
	}
	var request StepUpRequest
	if decode(r, &request) != nil {
		m.error(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	proof, err := repo.CreateLocalStepUp(r.Context(), actor.Scope, request)
	if errors.Is(err, ErrCurrentPasswordInvalid) {
		m.error(w, http.StatusUnauthorized, "STEP_UP_FAILED")
		return
	}
	if err != nil {
		m.permissionError(w, err)
		return
	}
	m.json(w, http.StatusOK, proof)
}
