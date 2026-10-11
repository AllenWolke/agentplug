package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type EnrollmentDecision struct {
	EnrollmentID  string
	TenantID      string
	DepartmentID  string
	ApplicationID string
	SubjectID     string
	ReviewerID    string
	Status        string
	Comment       string
	Revision      uint64
	TraceID       string
	OccurredAt    time.Time
}

// EnrollmentDecisionRecorder writes audit/outbox side effects through the
// same SQL transaction as the approve/reject state transition.
type EnrollmentDecisionRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentDecision) error

// EnrollmentVerificationRecorder writes only an encrypted notification payload
// into the same transaction that creates the enrollment row.
type EnrollmentVerificationRecorder func(context.Context, *sql.Tx, sharedkernel.Scope, EnrollmentCommand) error

func (s *SQLStore) SetEnrollmentDecisionRecorder(recorder EnrollmentDecisionRecorder) {
	if s != nil {
		s.enrollmentDecisionRecorder = recorder
	}
}

func (s *SQLStore) SetEnrollmentVerificationRecorder(recorder EnrollmentVerificationRecorder) {
	if s != nil {
		s.enrollmentVerificationRecorder = recorder
	}
}

func (s *SQLStore) EnsureEnrollmentSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS platform_identity_enrollment (
			id VARCHAR(64) PRIMARY KEY, username VARCHAR(128) NOT NULL, display_name VARCHAR(128) NOT NULL,
			contact_masked VARCHAR(255) NOT NULL, contact_hash VARCHAR(64) NOT NULL, password_hash VARCHAR(255) NOT NULL,
			tenant_id VARCHAR(128) NOT NULL, department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
			reason VARCHAR(500) NOT NULL, requested_agent_ids_json TEXT NOT NULL, status VARCHAR(32) NOT NULL,
			public_comment VARCHAR(500) NOT NULL DEFAULT '', reviewed_by VARCHAR(128) NOT NULL DEFAULT '',
			status_token_hash VARCHAR(64) NOT NULL, verify_token_hash VARCHAR(64) NOT NULL,
			verify_expires_at TIMESTAMPTZ(6) NULL, verify_attempts BIGINT CHECK (verify_attempts>=0 AND verify_attempts<=4294967295) NOT NULL DEFAULT 0,
			verified_at TIMESTAMPTZ(6) NULL, reviewed_at TIMESTAMPTZ(6) NULL, revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL,
			CONSTRAINT uq_identity_enrollment_username UNIQUE (username),
			CONSTRAINT uq_identity_enrollment_status_token UNIQUE (status_token_hash));
CREATE INDEX IF NOT EXISTS idx_identity_enrollment_scope ON platform_identity_enrollment (tenant_id,department_id,application_id,status,created_at);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_local_credential (
			principal_id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL,
			department_id VARCHAR(128) NOT NULL, application_id VARCHAR(128) NOT NULL,
			display_name VARCHAR(128) NOT NULL, password_hash VARCHAR(255) NOT NULL,
			auth_revision NUMERIC(20,0) CHECK (auth_revision>=0 AND auth_revision<=18446744073709551615) NOT NULL, active BOOLEAN NOT NULL,
			created_at TIMESTAMPTZ(6) NOT NULL, updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_identity_local_credential_tenant ON platform_identity_local_credential (tenant_id,principal_id,active);`,
		`CREATE TABLE IF NOT EXISTS platform_identity_registration_rate_limit (
			key_type VARCHAR(24) NOT NULL, key_hash VARCHAR(64) NOT NULL, bucket_start TIMESTAMPTZ(6) NOT NULL,
			attempts BIGINT CHECK (attempts>=0 AND attempts<=4294967295) NOT NULL, PRIMARY KEY (key_type,key_hash,bucket_start));
CREATE INDEX IF NOT EXISTS idx_identity_registration_rate_bucket ON platform_identity_registration_rate_limit (bucket_start);`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			return fmt.Errorf("identity enrollment schema: %w", err)
		}
	}
	return nil
}

func (s *SQLStore) CheckEnrollmentRateLimit(ctx context.Context, keys []RegistrationRateKey, now time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	bucket := now.UTC().Truncate(registrationRateWindow)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment rate check: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, key := range keys {
		if strings.TrimSpace(key.Value) == "" {
			continue
		}
		if key.Limit < 1 || key.Kind == "" {
			return ErrEnrollmentInvalid
		}
		hash := enrollmentTokenHash(strings.ToLower(strings.TrimSpace(key.Value)))
		_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_registration_rate_limit (key_type,key_hash,bucket_start,attempts)
			VALUES (?,?,?,1) ON CONFLICT (key_type,key_hash,bucket_start) DO UPDATE SET attempts=platform_identity_registration_rate_limit.attempts+1`), key.Kind, hash, bucket)
		if err != nil {
			return fmt.Errorf("increment enrollment rate counter: %w", err)
		}
		var attempts int
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT attempts FROM platform_identity_registration_rate_limit WHERE key_type=? AND key_hash=? AND bucket_start=? FOR UPDATE`), key.Kind, hash, bucket).Scan(&attempts); err != nil {
			return fmt.Errorf("read enrollment rate counter: %w", err)
		}
		if attempts > key.Limit {
			return ErrEnrollmentRateLimited
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment rate check: %w", err)
	}
	return nil
}

func (s *SQLStore) CreateEnrollment(ctx context.Context, item EnrollmentCommand) error {
	if s == nil || s.db == nil {
		return errors.New("identity database is required")
	}
	if err := validateEnrollmentCommand(item); err != nil {
		return err
	}
	requested, err := json.Marshal(item.RequestedAgentIDs)
	if err != nil {
		return fmt.Errorf("encode requested enrollment agent ids: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin identity enrollment creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_enrollment
		(id,username,display_name,contact_masked,contact_hash,password_hash,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,status_token_hash,verify_token_hash,verify_expires_at,verify_attempts,verified_at,reviewed_at,revision,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`), item.ID, item.Username, item.DisplayName, item.ContactMasked, item.ContactHash, item.PasswordHash,
		item.TenantID, item.DepartmentID, item.ApplicationID, item.Reason, string(requested), item.Status, "", "",
		item.StatusTokenHash, item.VerifyTokenHash, item.VerifyExpiresAt.UTC(), 0, nil, nil, item.Revision, item.CreatedAt.UTC(), item.UpdatedAt.UTC())
	if err != nil {
		return identityPersistenceError("create identity enrollment", err)
	}
	if item.VerificationCode != "" {
		if strings.TrimSpace(item.ContactForDelivery) == "" || !item.VerifyExpiresAt.After(item.CreatedAt) || s.enrollmentVerificationRecorder == nil {
			return ErrEnrollmentUnavailable
		}
		scope := sharedkernel.Scope{TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID}
		if err := s.enrollmentVerificationRecorder(ctx, tx, scope, item); err != nil {
			return fmt.Errorf("enqueue identity enrollment contact verification: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit identity enrollment creation: %w", err)
	}
	return nil
}

func (s *SQLStore) GetEnrollmentByToken(ctx context.Context, id, tokenHash string) (Enrollment, error) {
	if s == nil || s.db == nil {
		return Enrollment{}, errors.New("identity database is required")
	}
	return scanEnrollment(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE id=? AND status_token_hash=?`), id, tokenHash))
}

func (s *SQLStore) VerifyEnrollmentContact(ctx context.Context, id, statusTokenHash, codeHash string, now time.Time) (Enrollment, error) {
	if s == nil || s.db == nil {
		return Enrollment{}, errors.New("identity database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin identity contact verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	item, err := scanEnrollment(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE id=? AND status_token_hash=? FOR UPDATE`), id, statusTokenHash))
	if errors.Is(err, ErrEnrollmentNotFound) {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("load identity enrollment for verification: %w", err)
	}
	var status, storedCode string
	var expiry sql.NullTime
	var attempts uint
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,verify_token_hash,verify_expires_at,verify_attempts FROM platform_identity_enrollment WHERE id=?`), id).Scan(&status, &storedCode, &expiry, &attempts); err != nil {
		return Enrollment{}, fmt.Errorf("read identity verification state: %w", err)
	}
	if status == EnrollmentPending {
		if err := tx.Commit(); err != nil {
			return Enrollment{}, fmt.Errorf("commit repeated identity verification: %w", err)
		}
		return item, nil
	}
	if status != EnrollmentContactVerificationPending || !expiry.Valid || !expiry.Time.After(now) || attempts >= registrationMaxVerifyAttempts {
		return Enrollment{}, ErrEnrollmentConflict
	}
	if subtle.ConstantTimeCompare([]byte(storedCode), []byte(codeHash)) != 1 {
		result, updateErr := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET verify_attempts=verify_attempts+1,revision=revision+1,updated_at=? WHERE id=? AND status=? AND revision=?`), now.UTC(), id, EnrollmentContactVerificationPending, item.Revision)
		if updateErr != nil {
			return Enrollment{}, fmt.Errorf("count failed identity verification: %w", updateErr)
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil || rows != 1 {
			return Enrollment{}, ErrEnrollmentConflict
		}
		if err := tx.Commit(); err != nil {
			return Enrollment{}, fmt.Errorf("commit failed identity verification: %w", err)
		}
		return Enrollment{}, ErrVerificationRejected
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status=?,verified_at=?,verify_token_hash='',verify_expires_at=NULL,revision=revision+1,updated_at=? WHERE id=? AND status=? AND revision=?`), EnrollmentPending, now.UTC(), now.UTC(), id, EnrollmentContactVerificationPending, item.Revision)
	if err != nil {
		return Enrollment{}, fmt.Errorf("verify identity enrollment contact: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Enrollment{}, ErrEnrollmentConflict
	}
	item.Status, item.VerifiedAt, item.Revision, item.UpdatedAt = EnrollmentPending, &now, item.Revision+1, now
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit identity contact verification: %w", err)
	}
	return item, nil
}

func (s *SQLStore) WithdrawEnrollment(ctx context.Context, id, statusTokenHash string, expected uint64, now time.Time) (Enrollment, error) {
	if s == nil || s.db == nil {
		return Enrollment{}, errors.New("identity database is required")
	}
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status=?,verify_token_hash='',password_hash='',revision=revision+1,updated_at=?
		WHERE id=? AND status_token_hash=? AND revision=? AND status IN (?,?)`), EnrollmentWithdrawn, now.UTC(), id, statusTokenHash, expected, EnrollmentContactVerificationPending, EnrollmentPending)
	if err != nil {
		return Enrollment{}, fmt.Errorf("withdraw identity enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Enrollment{}, fmt.Errorf("read identity withdrawal result: %w", err)
	}
	if rows != 1 {
		return Enrollment{}, ErrEnrollmentConflict
	}
	return s.GetEnrollmentByToken(ctx, id, statusTokenHash)
}

func (s *SQLStore) ListEnrollments(ctx context.Context, scope EnrollmentScope, status string, page, pageSize int) ([]Enrollment, int64, error) {
	if s == nil || s.db == nil || !scope.valid() {
		return nil, 0, ErrEnrollmentInvalid
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	query := `SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE tenant_id=? AND department_id=? AND application_id=?`
	args := []any{scope.TenantID, scope.DepartmentID, scope.ApplicationID}
	countQuery := `SELECT COUNT(*) FROM platform_identity_enrollment WHERE tenant_id=? AND department_id=? AND application_id=?`
	if status != "" {
		query += ` AND status=?`
		countQuery += ` AND status=?`
		args = append(args, status)
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, sqlutil.Bind(countQuery), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scoped identity enrollments: %w", err)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(query), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scoped identity enrollments: %w", err)
	}
	defer rows.Close()
	items := make([]Enrollment, 0)
	for rows.Next() {
		item, err := scanEnrollment(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan identity enrollment: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate identity enrollments: %w", err)
	}
	return items, total, nil
}

func (s *SQLStore) GetEnrollment(ctx context.Context, scope EnrollmentScope, id string) (Enrollment, error) {
	if s == nil || s.db == nil || !scope.valid() {
		return Enrollment{}, ErrEnrollmentInvalid
	}
	return scanEnrollment(s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE id=? AND tenant_id=? AND department_id=? AND application_id=?`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID))
}

func (s *SQLStore) ApproveEnrollment(ctx context.Context, scope EnrollmentScope, id, reviewer string, expected uint64, comment, traceID string, grants []EnrollmentGrant, now time.Time) (Enrollment, error) {
	if s == nil || s.db == nil || !scope.valid() || strings.TrimSpace(reviewer) == "" || expected == 0 || len(grants) == 0 {
		return Enrollment{}, ErrEnrollmentInvalid
	}
	if s.enrollmentDecisionRecorder == nil {
		return Enrollment{}, ErrDecisionRecorderRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin identity enrollment approval: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return Enrollment{}, err
	}
	var mode string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), reviewer).Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, err
	}
	if err == nil && mode != "legacy" {
		return Enrollment{}, ErrPermissionDenied
	}
	item, err := scanEnrollment(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID))
	if errors.Is(err, ErrEnrollmentNotFound) {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("load identity enrollment for approval: %w", err)
	}
	if item.Status != EnrollmentPending || item.Revision != expected {
		return Enrollment{}, ErrEnrollmentConflict
	}
	if strings.EqualFold(item.Username, strings.TrimSpace(reviewer)) {
		return Enrollment{}, ErrEnrollmentSelfReview
	}
	var applicationExists int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=? AND status=? FOR UPDATE`), scope.ApplicationID, scope.TenantID, scope.DepartmentID, "active").Scan(&applicationExists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Enrollment{}, ErrApplicationNotFound
		}
		return Enrollment{}, fmt.Errorf("validate application for enrollment approval: %w", err)
	}
	requestedSet := make(map[string]struct{}, len(item.RequestedAgentIDs))
	for _, agentID := range item.RequestedAgentIDs {
		requestedSet[agentID] = struct{}{}
	}
	roles, _ := json.Marshal([]string{"operator"})
	groups, _ := json.Marshal([]string{})
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal (id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES (?,?,?,?,?,?,?,?)`), item.Username, PrincipalUser, item.TenantID, string(roles), string(groups), true, 1, now.UTC())
	if err != nil {
		return Enrollment{}, identityPersistenceError("create approved identity principal", err)
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential (principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at)
		SELECT username,tenant_id,department_id,application_id,display_name,password_hash,1,TRUE,?,? FROM platform_identity_enrollment WHERE id=? AND status=? AND revision=?`), now.UTC(), now.UTC(), id, EnrollmentPending, expected)
	if err != nil {
		return Enrollment{}, identityPersistenceError("create approved identity credential", err)
	}
	for _, grant := range grants {
		if _, requested := requestedSet[grant.AgentID]; !requested || grant.AgentInstanceID == "" || grant.AgentID == "" || len(grant.Actions) == 0 {
			return Enrollment{}, ErrEnrollmentInvalid
		}
		for _, action := range grant.Actions {
			value := Grant{ID: enrollmentGrantID(id, grant.AgentInstanceID, action), TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, AgentInstanceID: grant.AgentInstanceID, SubjectType: PrincipalUser, SubjectID: item.Username, Action: action, Effect: "allow", Status: GrantActive, Revision: 1}
			if err := value.Validate(); err != nil {
				return Enrollment{}, ErrEnrollmentInvalid
			}
			if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_grant (id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision,grant_key_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`), value.ID, value.TenantID, value.DepartmentID, value.ApplicationID, value.AgentInstanceID, value.SubjectType, value.SubjectID, value.Action, value.Effect, value.Status, value.Revision, grantKeyHash(value), now.UTC()); err != nil {
				return Enrollment{}, identityPersistenceError("create enrollment identity grant", err)
			}
		}
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status=?,reviewed_by=?,reviewed_at=?,public_comment=?,password_hash='',verify_token_hash='',verify_expires_at=NULL,revision=revision+1,updated_at=?
		WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status=? AND revision=?`), EnrollmentApproved, reviewer, now.UTC(), strings.TrimSpace(comment), now.UTC(), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, EnrollmentPending, expected)
	if err != nil {
		return Enrollment{}, fmt.Errorf("update approved identity enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Enrollment{}, ErrEnrollmentConflict
	}
	item.Status, item.ReviewedBy, item.ReviewedAt, item.PublicComment, item.Revision, item.UpdatedAt = EnrollmentApproved, reviewer, &now, strings.TrimSpace(comment), item.Revision+1, now
	decision := EnrollmentDecision{EnrollmentID: item.ID, TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, SubjectID: item.Username, ReviewerID: reviewer, Status: EnrollmentApproved, Comment: strings.TrimSpace(comment), Revision: item.Revision, TraceID: traceID, OccurredAt: now}
	if err := s.enrollmentDecisionRecorder(ctx, tx, scope.shared(), decision); err != nil {
		return Enrollment{}, fmt.Errorf("record identity enrollment approval: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit identity enrollment approval: %w", err)
	}
	return item, nil
}

func (s *SQLStore) RejectEnrollment(ctx context.Context, scope EnrollmentScope, id, reviewer string, expected uint64, comment, traceID string, now time.Time) (Enrollment, error) {
	if s == nil || s.db == nil || !scope.valid() || strings.TrimSpace(reviewer) == "" || expected == 0 {
		return Enrollment{}, ErrEnrollmentInvalid
	}
	if s.enrollmentDecisionRecorder == nil {
		return Enrollment{}, ErrDecisionRecorderRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin identity enrollment rejection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockPermissionContinuity(ctx, tx); err != nil {
		return Enrollment{}, err
	}
	var mode string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT policy_mode FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), reviewer).Scan(&mode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, err
	}
	if err == nil && mode != "legacy" {
		return Enrollment{}, ErrPermissionDenied
	}
	item, err := scanEnrollment(tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,username,display_name,contact_masked,tenant_id,department_id,application_id,reason,requested_agent_ids_json,status,public_comment,reviewed_by,revision,verified_at,reviewed_at,created_at,updated_at
		FROM platform_identity_enrollment WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID))
	if errors.Is(err, ErrEnrollmentNotFound) {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("load identity enrollment for rejection: %w", err)
	}
	if item.Status != EnrollmentPending || item.Revision != expected {
		return Enrollment{}, ErrEnrollmentConflict
	}
	if strings.EqualFold(item.Username, strings.TrimSpace(reviewer)) {
		return Enrollment{}, ErrEnrollmentSelfReview
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_enrollment SET status=?,reviewed_by=?,reviewed_at=?,public_comment=?,password_hash='',verify_token_hash='',verify_expires_at=NULL,revision=revision+1,updated_at=?
		WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND status=? AND revision=?`), EnrollmentRejected, reviewer, now.UTC(), strings.TrimSpace(comment), now.UTC(), id, scope.TenantID, scope.DepartmentID, scope.ApplicationID, EnrollmentPending, expected)
	if err != nil {
		return Enrollment{}, fmt.Errorf("update rejected identity enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return Enrollment{}, ErrEnrollmentConflict
	}
	item.Status, item.ReviewedBy, item.ReviewedAt, item.PublicComment, item.Revision, item.UpdatedAt = EnrollmentRejected, reviewer, &now, strings.TrimSpace(comment), item.Revision+1, now
	decision := EnrollmentDecision{EnrollmentID: item.ID, TenantID: item.TenantID, DepartmentID: item.DepartmentID, ApplicationID: item.ApplicationID, SubjectID: item.Username, ReviewerID: reviewer, Status: EnrollmentRejected, Comment: strings.TrimSpace(comment), Revision: item.Revision, TraceID: traceID, OccurredAt: now}
	if err := s.enrollmentDecisionRecorder(ctx, tx, scope.shared(), decision); err != nil {
		return Enrollment{}, fmt.Errorf("record identity enrollment rejection: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit identity enrollment rejection: %w", err)
	}
	return item, nil
}

func (s *SQLStore) VerifyEnrollmentCredentials(ctx context.Context, username, password string) (LocalIdentity, error) {
	if s == nil || s.db == nil {
		return LocalIdentity{}, errors.New("identity database is required")
	}
	return s.verifyCredentialLookup(ctx, username, password)
}

func (s *SQLStore) verifyCredentialLookup(ctx context.Context, username, password string) (LocalIdentity, error) {
	var identity LocalIdentity
	var encodedHash, rolesJSON string
	var credentialActive, principalActive bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.principal_id,c.tenant_id,c.department_id,c.application_id,c.display_name,c.password_hash,c.auth_revision,c.active,p.roles_json,p.active
		FROM platform_identity_local_credential c JOIN platform_identity_principal p ON p.principal_type=? AND p.id=c.principal_id AND p.tenant_id=c.tenant_id
		JOIN platform_identity_tenant t ON t.id=c.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=c.department_id AND d.tenant_id=c.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=c.application_id AND a.tenant_id=c.tenant_id AND a.department_id=c.department_id AND a.status='active'
		WHERE c.principal_id=?`), PrincipalUser, username).Scan(&identity.PrincipalID, &identity.TenantID, &identity.DepartmentID, &identity.ApplicationID, &identity.DisplayName, &encodedHash, &identity.AuthRevision, &credentialActive, &rolesJSON, &principalActive)
	if err != nil || !credentialActive || !principalActive || !verifyEnrollmentPassword(encodedHash, password) {
		// Do comparable work for a missing username to reduce account probing.
		if errors.Is(err, sql.ErrNoRows) {
			_ = verifyEnrollmentPassword(dummyEnrollmentPasswordHash, password)
		}
		return LocalIdentity{}, ErrEnrollmentInvalid
	}
	identity.Username = identity.PrincipalID
	identity.Roles, err = authenticationRoleProjection(ctx, s.db, identity.PrincipalID, rolesJSON)
	if err != nil {
		return LocalIdentity{}, err
	}
	return identity, nil
}

func (s *SQLStore) ValidateEnrollmentSession(ctx context.Context, username string, scope EnrollmentScope, revision uint64) (LocalIdentity, error) {
	if s == nil || s.db == nil || !scope.valid() || revision == 0 {
		return LocalIdentity{}, ErrEnrollmentInvalid
	}
	var identity LocalIdentity
	var rolesJSON string
	var credentialActive, principalActive bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT c.principal_id,c.tenant_id,c.department_id,c.application_id,c.display_name,c.auth_revision,c.active,p.roles_json,p.active
		FROM platform_identity_local_credential c JOIN platform_identity_principal p ON p.principal_type=? AND p.id=c.principal_id AND p.tenant_id=c.tenant_id
		JOIN platform_identity_tenant t ON t.id=c.tenant_id AND t.status='active'
		JOIN platform_identity_department d ON d.id=c.department_id AND d.tenant_id=c.tenant_id AND d.status='active'
		JOIN platform_identity_application a ON a.id=c.application_id AND a.tenant_id=c.tenant_id AND a.department_id=c.department_id AND a.status='active'
		WHERE c.principal_id=? AND c.tenant_id=?`), PrincipalUser, username, scope.TenantID).
		Scan(&identity.PrincipalID, &identity.TenantID, &identity.DepartmentID, &identity.ApplicationID, &identity.DisplayName, &identity.AuthRevision, &credentialActive, &rolesJSON, &principalActive)
	if err != nil || !credentialActive || !principalActive || identity.AuthRevision != revision {
		return LocalIdentity{}, ErrEnrollmentInvalid
	}
	identity.Roles, err = authenticationRoleProjection(ctx, s.db, identity.PrincipalID, rolesJSON)
	if err != nil {
		return LocalIdentity{}, err
	}
	identity.Username = identity.PrincipalID
	if scope.DepartmentID != identity.DepartmentID || scope.ApplicationID != identity.ApplicationID {
		if err := validateWorkspace(ctx, s.db, identity.PrincipalID, scope, s.clock().UTC()); err != nil {
			return LocalIdentity{}, err
		}
		identity.DepartmentID, identity.ApplicationID = scope.DepartmentID, scope.ApplicationID
	}
	return identity, nil
}

type enrollmentScanner interface{ Scan(...any) error }

func scanEnrollment(scanner enrollmentScanner) (Enrollment, error) {
	var item Enrollment
	var requestedJSON string
	var verified, reviewed sql.NullTime
	err := scanner.Scan(&item.ID, &item.Username, &item.DisplayName, &item.Contact, &item.TenantID, &item.DepartmentID, &item.ApplicationID, &item.Reason, &requestedJSON, &item.Status, &item.PublicComment, &item.ReviewedBy, &item.Revision, &verified, &reviewed, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Enrollment{}, ErrEnrollmentNotFound
		}
		return Enrollment{}, err
	}
	if err := json.Unmarshal([]byte(requestedJSON), &item.RequestedAgentIDs); err != nil {
		return Enrollment{}, fmt.Errorf("decode requested identity enrollment agents: %w", err)
	}
	if verified.Valid {
		item.VerifiedAt = &verified.Time
	}
	if reviewed.Valid {
		item.ReviewedAt = &reviewed.Time
	}
	return item, nil
}

func validateEnrollmentCommand(item EnrollmentCommand) error {
	if strings.TrimSpace(item.ID) == "" || !enrollmentUsernamePattern.MatchString(item.Username) || len(item.DisplayName) < 2 || item.ContactMasked == "" || len(item.ContactHash) != 64 || item.PasswordHash == "" || item.TenantID == "" || item.DepartmentID == "" || item.ApplicationID == "" || len(item.Reason) < 10 || item.Status != EnrollmentContactVerificationPending || len(item.StatusTokenHash) != 64 || len(item.VerifyTokenHash) != 64 || item.Revision != 1 || !item.VerifyExpiresAt.After(item.CreatedAt) {
		return ErrEnrollmentInvalid
	}
	if (item.ContactForDelivery == "") != (item.VerificationCode == "") {
		return ErrEnrollmentInvalid
	}
	return nil
}

func enrollmentGrantID(enrollmentID, installationID, action string) string {
	sum := sha256.Sum256([]byte(enrollmentID + "\x00" + installationID + "\x00" + action))
	return "ienr_" + hex.EncodeToString(sum[:16])
}

var _ EnrollmentRepository = (*SQLStore)(nil)
var _ EnrollmentCredentials = (*SQLStore)(nil)
