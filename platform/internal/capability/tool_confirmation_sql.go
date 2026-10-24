package capability

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

var ErrToolApprovalDenied = errors.New("tool approval denied or unavailable")

type ToolConfirmationAuthority interface {
	CheckApproval(context.Context, ToolConfirmationClaims) error
}

// The root authorizer must validate current browser session, run ownership,
// approved policy and exact action-bound step-up proof in the same transaction.
type ToolApprovalAuthorizer func(context.Context, *sql.Tx, sharedkernel.Scope, ToolConfirmationClaims, string, string) error

type SQLToolApprovalStore struct {
	db        *sql.DB
	audit     audit.TxRecorder
	authorize ToolApprovalAuthorizer
}

func NewSQLToolApprovalStore(db *sql.DB) (*SQLToolApprovalStore, error) {
	if db == nil {
		return nil, ErrToolApprovalDenied
	}
	return &SQLToolApprovalStore{db: db}, nil
}
func (s *SQLToolApprovalStore) SetAuditRecorder(recorder audit.TxRecorder) { s.audit = recorder }
func (s *SQLToolApprovalStore) SetAuthorizer(authorizer ToolApprovalAuthorizer) {
	s.authorize = authorizer
}

func (s *SQLToolApprovalStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_tool_approval (
 approval_id VARCHAR(128) PRIMARY KEY, actor_id VARCHAR(128) NOT NULL,
 scope_hash VARCHAR(64) NOT NULL, claims_hash VARCHAR(64) NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_tool_approval_scope ON platform_tool_approval(scope_hash,expires_at);`)
	return err
}

func toolApprovalDigest(claims ToolConfirmationClaims) string {
	raw, _ := json.Marshal(claims)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func (s *SQLToolApprovalStore) CheckApproval(ctx context.Context, claims ToolConfirmationClaims) error {
	if s == nil || s.db == nil {
		return ErrToolApprovalDenied
	}
	var exists bool
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_tool_approval WHERE approval_id=? AND actor_id=? AND scope_hash=? AND claims_hash=? AND revoked=FALSE AND expires_at>clock_timestamp())`), claims.ApprovalID, claims.ActorID, claims.ScopeHash, toolApprovalDigest(claims)).Scan(&exists)
	if err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if !exists {
		return ErrToolApprovalDenied
	}
	return nil
}

// CheckApprovalTx fences a previously committed approval in the caller's
// transaction. The caller must acquire IAM and Run/checkpoint fences first;
// revocation takes the same approval row's UPDATE lock. No new grant is issued.
func (s *SQLToolApprovalStore) CheckApprovalTx(ctx context.Context, tx *sql.Tx, claims ToolConfirmationClaims) error {
	if s == nil || s.db == nil || tx == nil || claims.Version != "tool-confirmation/v1" || claims.ApprovalID == "" || claims.ActorID == "" || claims.ScopeHash == "" || !validPendingConfirmationReference(claims) {
		return ErrToolApprovalDenied
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	var digest string
	var revoked bool
	var expires time.Time
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT claims_hash,revoked,expires_at FROM platform_tool_approval WHERE approval_id=? AND actor_id=? AND scope_hash=? FOR SHARE`), claims.ApprovalID, claims.ActorID, claims.ScopeHash).Scan(&digest, &revoked, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if err != nil || revoked || digest != toolApprovalDigest(claims) {
		return ErrToolApprovalDenied
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if !expires.After(now) || claims.IssuedAt <= 0 || claims.IssuedAt > now.Unix()+5 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt <= now.Unix() || claims.ExpiresAt-claims.IssuedAt > 300 {
		return ErrToolApprovalDenied
	}
	return nil
}

// ResumeApproved commits the owner Run CAS and its approval Audit/Outbox as
// one transaction. Composition callbacks acquire current IAM, ancestor/target
// Run and pending checkpoint fences, then save only an approved reference.
// Neither callback may commit, enqueue, invoke remotely or persist a token.
func (s *SQLToolApprovalStore) ResumeApproved(ctx context.Context, scope sharedkernel.Scope, claims ToolConfirmationClaims, authorize func(context.Context, *sql.Tx) error, prepare func(context.Context, *sql.Tx) error) error {
	if s == nil || s.db == nil || s.audit == nil || authorize == nil || prepare == nil || ctx.Err() != nil || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || claims.ActorID != scope.PrincipalID || claims.ScopeHash != ToolReceiptScopeHash(scope) || claims.AuthorizationEpoch != scope.AuthorizationEpoch || claims.PendingKey == "" || !validPendingConfirmationReference(claims) {
		return ErrToolApprovalDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	if err = authorize(ctx, tx); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if err = s.CheckApprovalTx(ctx, tx, claims); err != nil {
		return err
	}
	if err = prepare(ctx, tx); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = s.record(tx, scope, claims, "tool.approval.resume", now); err != nil {
		return err
	}
	// Locks prevent revocation races; time still advances during Audit/Outbox.
	// An approval that expired meanwhile must roll back the Run change too.
	if err = s.CheckApprovalTx(ctx, tx, claims); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLToolApprovalStore) Approve(ctx context.Context, scope sharedkernel.Scope, claims ToolConfirmationClaims, proof string) error {
	if !validPendingConfirmationReference(claims) {
		return ErrToolApprovalDenied
	}
	if s.audit == nil || s.authorize == nil || proof == "" || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || claims.ActorID != scope.PrincipalID || claims.ScopeHash != ToolReceiptScopeHash(scope) || claims.AuthorizationEpoch != scope.AuthorizationEpoch || claims.Version != "tool-confirmation/v1" || claims.ApprovalID == "" || len(claims.ApprovalID) > 128 || claims.CallID == "" || claims.ToolName == "" || claims.PolicyHash == "" || claims.Fingerprint == "" || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 300 {
		return ErrToolApprovalDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	if err = s.authorize(ctx, tx, scope, claims, "tool.approval.approve", proof); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if claims.IssuedAt > now.Unix()+5 || now.Unix() >= claims.ExpiresAt {
		return ErrToolApprovalDenied
	}
	digest := toolApprovalDigest(claims)
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_tool_approval(approval_id,actor_id,scope_hash,claims_hash,expires_at,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(approval_id) DO NOTHING`), claims.ApprovalID, claims.ActorID, claims.ScopeHash, digest, time.Unix(claims.ExpiresAt, 0), now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		var existing string
		var revoked bool
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT claims_hash,revoked FROM platform_tool_approval WHERE approval_id=? FOR UPDATE`), claims.ApprovalID).Scan(&existing, &revoked); err != nil {
			return errors.Join(ErrToolApprovalDenied, err)
		}
		if existing != digest || revoked {
			return ErrToolApprovalDenied
		}
		return tx.Commit()
	}
	if err = s.record(tx, scope, claims, "tool.approval.approve", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLToolApprovalStore) Revoke(ctx context.Context, scope sharedkernel.Scope, claims ToolConfirmationClaims, proof string) error {
	if s.audit == nil || s.authorize == nil || proof == "" || scope.ValidateTrusted() != nil || claims.ActorID != scope.PrincipalID || claims.ScopeHash != ToolReceiptScopeHash(scope) {
		return ErrToolApprovalDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	if err = s.authorize(ctx, tx, scope, claims, "tool.approval.revoke", proof); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	var digest string
	var revoked bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT claims_hash,revoked FROM platform_tool_approval WHERE approval_id=? AND actor_id=? AND scope_hash=? FOR UPDATE`), claims.ApprovalID, scope.PrincipalID, claims.ScopeHash).Scan(&digest, &revoked); err != nil {
		return errors.Join(ErrToolApprovalDenied, err)
	}
	if digest != toolApprovalDigest(claims) {
		return ErrToolApprovalDenied
	}
	if revoked {
		return tx.Commit()
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_tool_approval SET revoked=TRUE,revoked_at=? WHERE approval_id=?`), now, claims.ApprovalID); err != nil {
		return err
	}
	if err = s.record(tx, scope, claims, "tool.approval.revoke", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLToolApprovalStore) record(tx *sql.Tx, scope sharedkernel.Scope, claims ToolConfirmationClaims, action string, now time.Time) error {
	eventHash := sha256.Sum256([]byte(action + "\x00" + claims.ApprovalID))
	return s.audit.RecordTx(tx, audit.Event{ID: "tool-approval-" + hex.EncodeToString(eventHash[:]), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "tool_approval", AggregateID: claims.ApprovalID, Action: action, Outcome: "success", Summary: "claims_hash=" + toolApprovalDigest(claims), CreatedAt: now})
}
