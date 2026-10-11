package conversation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"time"
)

var ErrErasureLease = errors.New("conversation erasure lease unavailable")
var ErrErasureBusy = errors.New("conversation erasure has recoverable runs")
var ErrErasureRetention = errors.New("conversation retention period has not ended")

// The scope is read from the committed job, never from a worker HTTP header.
type ErasureClaim struct {
	RequestID  string
	Scope      Scope
	Worker     string
	Revision   uint64
	Attempts   int
	LeaseUntil time.Time
}

type ErasureReceipt struct {
	Version       string           `json:"version"`
	RequestID     string           `json:"request_id"`
	SessionID     string           `json:"session_id"`
	TenantID      string           `json:"tenant_id"`
	DepartmentID  string           `json:"department_id"`
	ApplicationID string           `json:"application_id"`
	ApproverID    string           `json:"approver_id"`
	Worker        string           `json:"worker"`
	ErasedAt      time.Time        `json:"erased_at"`
	DeletedRows   map[string]int64 `json:"deleted_rows"`
	Digest        string           `json:"digest"`
}

type ErasureAuthorization func(context.Context, Scope, SessionResource) error
type ErasureQuiescence func(context.Context, *sql.Tx, Scope, string) (bool, error)
type ErasureRecorder func(context.Context, *sql.Tx, Scope, ErasureReceipt) error

func (s *SQLStore) SetErasurePorts(authorize ErasureAuthorization, quiescent ErasureQuiescence, record ErasureRecorder) {
	s.erasureAuthorize, s.erasureQuiescent, s.erasureRecorder = authorize, quiescent, record
}

// Deployment migration only. No application or worker startup DDL.
func (s *SQLStore) EnsureErasureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE IF NOT EXISTS platform_conversation_erasure (
	 request_id VARCHAR(128) NOT NULL PRIMARY KEY,
	 tenant_id VARCHAR(128) NOT NULL,department_id VARCHAR(128) NOT NULL,application_id VARCHAR(128) NOT NULL,
	 approver_id VARCHAR(128) NOT NULL,trace_id VARCHAR(128) NOT NULL,
	 status VARCHAR(32) NOT NULL,attempts INT NOT NULL,revision NUMERIC(20,0) CHECK (revision>=0 AND revision<=18446744073709551615) NOT NULL,
	 not_before TIMESTAMPTZ(6) NOT NULL,last_activity_at TIMESTAMPTZ(6) NOT NULL,
	 worker VARCHAR(128) NOT NULL,lease_until TIMESTAMPTZ(6) NULL,last_error_code VARCHAR(64) NOT NULL,
	 receipt_json TEXT NOT NULL,updated_at TIMESTAMPTZ(6) NOT NULL);
CREATE INDEX IF NOT EXISTS idx_conversation_erasure_queue ON platform_conversation_erasure (status,not_before,lease_until);
CREATE INDEX IF NOT EXISTS idx_conversation_erasure_scope ON platform_conversation_erasure (tenant_id,department_id,application_id,request_id);`))
	return err
}

func (s *SQLStore) enqueueErasure(ctx context.Context, tx *sql.Tx, scope Scope, item DeletionRequest, lastActivity time.Time) error {
	_, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_conversation_erasure(request_id,tenant_id,department_id,application_id,approver_id,trace_id,status,attempts,revision,not_before,last_activity_at,worker,lease_until,last_error_code,receipt_json,updated_at) VALUES(?,?,?,?,?,?,'pending',0,1,?,?,'',NULL,'','',?)`), item.ID, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.PrincipalID, scope.TraceID, item.ApprovedAt.Add(24*time.Hour), lastActivity, item.ApprovedAt)
	return err
}

func (s *SQLStore) ClaimErasure(ctx context.Context, worker string, lease time.Duration) (ErasureClaim, error) {
	if worker == "" || len(worker) > 128 || lease < time.Second || lease > 5*time.Minute {
		return ErasureClaim{}, ErrInvalidQuery
	}
	if s.deletionGuard == nil || s.deletionReplay == nil || s.erasureAuthorize == nil || s.erasureQuiescent == nil || s.erasureRecorder == nil {
		return ErasureClaim{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErasureClaim{}, err
	}
	defer tx.Rollback()
	now := s.clock().UTC().Truncate(time.Microsecond)
	var c ErasureClaim
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT request_id,tenant_id,department_id,application_id,approver_id,trace_id,attempts,revision FROM platform_conversation_erasure WHERE ((status='pending' AND not_before<=?) OR (status='processing' AND lease_until<=?)) ORDER BY not_before,request_id LIMIT 1 FOR UPDATE SKIP LOCKED`), now, now).Scan(&c.RequestID, &c.Scope.TenantID, &c.Scope.DepartmentID, &c.Scope.ApplicationID, &c.Scope.PrincipalID, &c.Scope.TraceID, &c.Attempts, &c.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return ErasureClaim{}, ErrNotFound
	}
	if err != nil {
		return ErasureClaim{}, err
	}
	if c.Attempts >= 10 {
		if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_erasure SET status='failed',lease_until=NULL,last_error_code='attempts_exhausted',updated_at=? WHERE request_id=?`), now, c.RequestID); err != nil {
			return ErasureClaim{}, err
		}
		if err = tx.Commit(); err != nil {
			return ErasureClaim{}, err
		}
		return ErasureClaim{}, ErrNotFound
	}
	c.Scope.PrincipalType = "user"
	c.Worker, c.LeaseUntil = worker, now.Add(lease)
	c.Attempts++
	c.Revision++
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_erasure SET status='processing',attempts=?,revision=?,worker=?,lease_until=?,updated_at=? WHERE request_id=?`), c.Attempts, c.Revision, worker, c.LeaseUntil, now, c.RequestID)
	if err != nil {
		return ErasureClaim{}, err
	}
	if err = tx.Commit(); err != nil {
		return ErasureClaim{}, err
	}
	return c, nil
}

// No payload leaves this transaction. SQL rollback restores all deleted rows.
func (s *SQLStore) CompleteErasure(ctx context.Context, claim ErasureClaim) (ErasureReceipt, error) {
	if s.deletionGuard == nil || s.deletionReplay == nil || s.erasureAuthorize == nil || s.erasureQuiescent == nil || s.erasureRecorder == nil {
		return ErasureReceipt{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErasureReceipt{}, err
	}
	defer tx.Rollback()
	if err = s.deletionGuard(ctx, tx); err != nil {
		return ErasureReceipt{}, err
	}
	var c ErasureClaim
	var status string
	var lease sql.NullTime
	var lastActivity time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT tenant_id,department_id,application_id,approver_id,trace_id,status,worker,revision,lease_until,last_activity_at FROM platform_conversation_erasure WHERE request_id=? FOR UPDATE`), claim.RequestID).Scan(&c.Scope.TenantID, &c.Scope.DepartmentID, &c.Scope.ApplicationID, &c.Scope.PrincipalID, &c.Scope.TraceID, &status, &c.Worker, &c.Revision, &lease, &lastActivity)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if status != "processing" || c.Worker != claim.Worker || c.Revision != claim.Revision || !lease.Valid || !s.clock().Before(lease.Time) {
		return ErasureReceipt{}, ErrErasureLease
	}
	c.Scope.PrincipalType = "user"
	var request DeletionRequest
	var approved sql.NullTime
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,session_id,owner_id,reason,status,requested_at,approved_at FROM platform_conversation_deletion WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? FOR UPDATE`), claim.RequestID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID).Scan(&request.ID, &request.SessionID, &request.OwnerID, &request.Reason, &request.Status, &request.RequestedAt, &approved)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if !approved.Valid || request.Status != "approved" || request.OwnerID == c.Scope.PrincipalID {
		return ErasureReceipt{}, ErrForbidden
	}
	request.ApprovedAt = approved.Time
	if s.clock().Before(request.ApprovedAt.Add(24 * time.Hour)) {
		return ErasureReceipt{}, ErrErasureRetention
	}
	matched, err := s.deletionReplay(ctx, tx, c.Scope, request)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if !matched {
		return ErasureReceipt{}, ErrForbidden
	}
	var resource SessionResource
	var kind string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT id,owner_id,principal_type,installation_id,agent_id,agent_version_id,status,kind FROM platform_conversation_session WHERE id=? AND tenant_id=? AND department_id=? AND application_id=? AND owner_id=? FOR UPDATE`), request.SessionID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID, request.OwnerID).Scan(&resource.ID, &resource.OwnerID, &resource.PrincipalType, &resource.InstallationID, &resource.AgentID, &resource.AgentVersionID, &status, &kind)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if status != "deleted" {
		return ErasureReceipt{}, ErrForbidden
	}
	if err = s.erasureAuthorize(ctx, c.Scope, resource); err != nil {
		return ErasureReceipt{}, err
	}
	var held int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_conversation_legal_hold WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=? AND status='active'`), resource.ID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID).Scan(&held); err != nil {
		return ErasureReceipt{}, err
	}
	if held > 0 {
		return ErasureReceipt{}, ErrLegalHold
	}
	var days int
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT retention_days FROM platform_conversation_retention_policy WHERE tenant_id=? AND department_id=? AND application_id=? AND kind=? AND enabled=TRUE`), c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID, kind).Scan(&days)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ErasureReceipt{}, err
	}
	if err == nil && lastActivity.Add(time.Duration(days)*24*time.Hour).After(s.clock()) {
		return ErasureReceipt{}, ErrErasureRetention
	}
	quiet, err := s.erasureQuiescent(ctx, tx, c.Scope, resource.ID)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if !quiet {
		return ErasureReceipt{}, ErrErasureBusy
	}
	receipt := ErasureReceipt{Version: "conversation-payload-erasure/v1", RequestID: request.ID, SessionID: resource.ID, TenantID: c.Scope.TenantID, DepartmentID: c.Scope.DepartmentID, ApplicationID: c.Scope.ApplicationID, ApproverID: c.Scope.PrincipalID, Worker: c.Worker, ErasedAt: s.clock().UTC().Truncate(time.Microsecond), DeletedRows: map[string]int64{}}
	// Fixed table names, fixed scope predicates; never accept a table name from a job.
	for _, statement := range []struct{ name, sql string }{
		{"messages", `DELETE FROM platform_conversation_message WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=?`},
		{"revisions", `DELETE FROM platform_conversation_revision WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=?`},
		{"exports", `DELETE FROM platform_conversation_export WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=?`},
		{"shares", `DELETE FROM platform_conversation_share WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=?`},
	} {
		result, e := tx.ExecContext(ctx, sqlutil.Bind(statement.sql), resource.ID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID)
		if e != nil {
			return ErasureReceipt{}, e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return ErasureReceipt{}, e
		}
		receipt.DeletedRows[statement.name] = n
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_session SET title='',preview='',message_count=0,can_continue=FALSE,revision=revision+1,updated_at=? WHERE id=? AND tenant_id=? AND department_id=? AND application_id=?`), receipt.ErasedAt, resource.ID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID); err != nil {
		return ErasureReceipt{}, err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_deletion SET reason='' WHERE session_id=? AND tenant_id=? AND department_id=? AND application_id=?`), resource.ID, c.Scope.TenantID, c.Scope.DepartmentID, c.Scope.ApplicationID); err != nil {
		return ErasureReceipt{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return ErasureReceipt{}, err
	}
	sum := sha256.Sum256(encoded)
	receipt.Digest = hex.EncodeToString(sum[:])
	encoded, err = json.Marshal(receipt)
	if err != nil {
		return ErasureReceipt{}, err
	}
	if err = s.erasureRecorder(ctx, tx, c.Scope, receipt); err != nil {
		return ErasureReceipt{}, err
	}
	if err = s.erasureAuthorize(ctx, c.Scope, resource); err != nil {
		return ErasureReceipt{}, err
	}
	if !s.clock().Before(lease.Time) {
		return ErasureReceipt{}, ErrErasureLease
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_erasure SET status='completed',receipt_json=?,lease_until=NULL,last_error_code='',updated_at=? WHERE request_id=?`), string(encoded), receipt.ErasedAt, request.ID); err != nil {
		return ErasureReceipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return ErasureReceipt{}, err
	}
	return receipt, nil
}

func (s *SQLStore) RetryErasure(ctx context.Context, claim ErasureClaim, cause error) error {
	code := "execution_failed"
	switch {
	case errors.Is(cause, ErrForbidden):
		code = "permission_denied"
	case errors.Is(cause, ErrLegalHold):
		code = "legal_hold"
	case errors.Is(cause, ErrErasureBusy):
		code = "run_not_quiescent"
	case errors.Is(cause, ErrErasureRetention):
		code = "retention_not_elapsed"
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_conversation_erasure SET status=CASE WHEN attempts>=10 THEN 'failed' ELSE 'pending' END,worker='',lease_until=NULL,last_error_code=?,not_before=?,updated_at=? WHERE request_id=? AND status='processing' AND worker=? AND revision=?`), code, now.Add(15*time.Minute), now, claim.RequestID, claim.Worker, claim.Revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrErasureLease
	}
	return nil
}
