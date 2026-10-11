package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// TryCancelUndispatched consumes a positive current-protocol claim, never an
// assumed SDK exit. Dispatch and this cancellation both lock the same Run and
// journal before transport; after cancellation no delayed command can commit.
// 已领取未投递的世代在同一 Run 事务内封禁；缺少领取证明不等于停止。
func (s *SQLStore) TryCancelUndispatched(ctx context.Context, pending platformruntime.Run) (bool, error) {
	if s == nil || s.db == nil || ctx == nil || pending.Status != platformruntime.StatusCancelling || pending.Revision < 3 || pending.LeaseToken == "" || pending.Scope.ValidateTrusted() != nil || pending.ID != pending.Scope.RunID {
		return false, platformruntime.ErrInvalidRequest
	}
	_, err := s.cancelWithGuard(ctx, pending.ID, pending.Revision, nil, nil, nil, func(ctx context.Context, tx *sql.Tx, actual platformruntime.Run) error {
		if actual.Status != pending.Status || actual.Scope != pending.Scope || actual.LeaseToken != pending.LeaseToken || actual.AgentEndpoint != pending.AgentEndpoint || !bytes.Equal(actual.RequestJSON, pending.RequestJSON) || !bytes.Equal(actual.ResumeInputJSON, pending.ResumeInputJSON) {
			return platformruntime.ErrRevisionConflict
		}
		return s.verifyUndispatchedCancelTx(ctx, tx, actual)
	})
	if errors.Is(err, ErrStopEvidenceAbsent) {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLStore) verifyUndispatchedCancelTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) error {
	var request contract.ExecuteRequest
	if run.AgentEndpoint == "" || json.Unmarshal(run.RequestJSON, &request) != nil || request.ProtocolVersion != contract.ProtocolVersion || (request.Operation != "invoke" && request.Operation != "run") || request.ResumeInput != nil || request.Scope.RunID != run.ID || request.IdempotencyKey != run.IdempotencyKey {
		return ErrStopEvidenceAbsent
	}
	c := request.Scope
	scope := run.Scope
	if c != (contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, InstallationID: scope.InstallationID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID, DelegationDepth: c.DelegationDepth}) || c.DelegationDepth > 4 || (scope.ParentRunID == "" && c.DelegationDepth != 0) || (scope.ParentRunID != "" && c.DelegationDepth == 0) {
		return ErrStopEvidenceAbsent
	}
	leaseHash := generationJournalHash([]byte(run.LeaseToken))
	requestHash, resumeHash := generationJournalHash(run.RequestJSON), generationJournalHash(run.ResumeInputJSON)
	var epoch, count int
	var version, priorStatus, storedLease, storedRequest, storedResume string
	var priorRevision, claimRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_execution_generation_claim_journal WHERE run_id=? AND lease_token_hash=?`), run.ID, leaseHash).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrStopEvidenceAbsent
	}
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash FROM platform_execution_generation_claim_journal WHERE run_id=? AND lease_token_hash=? FOR SHARE`), run.ID, leaseHash).
		Scan(&epoch, &version, &priorStatus, &priorRevision, &claimRevision, &storedLease, &storedRequest, &storedResume); err != nil {
		return err
	}
	if epoch != generationJournalProtocolEpoch || version != generationJournalProtocolVersion || priorRevision+1 != claimRevision || storedLease != leaseHash || storedRequest != requestHash || storedResume != resumeHash {
		return ErrStopEvidenceAbsent
	}
	switch priorStatus {
	case "accepted":
		if priorRevision != 1 || claimRevision != 2 || (run.Revision != 3 && run.Revision != 4) || len(run.ResumeInputJSON) != 0 {
			return ErrStopEvidenceAbsent
		}
	case "running":
		if run.Revision != claimRevision+1 || priorRevision < 2 || len(run.ResumeInputJSON) == 0 {
			return ErrStopEvidenceAbsent
		}
		// A reclaim of a possibly active handler is not a paused business resume.
		// Only the committed waiting -> running transition proves this admission.
		var resumed bool
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type='status' AND payload::jsonb->>'from'='waiting' AND payload::jsonb->>'to'='running' AND payload::jsonb->>'revision'=?)`), run.ID, strconv.FormatUint(priorRevision, 10)).Scan(&resumed); err != nil {
			return err
		}
		if !resumed {
			return ErrStopEvidenceAbsent
		}
	default:
		return ErrStopEvidenceAbsent
	}
	var sent, projected bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_generation_dispatch_journal WHERE run_id=? AND (lease_token_hash=? OR claim_revision>=?)),EXISTS(SELECT 1 FROM platform_execution_dispatch_command WHERE run_id=? AND revision>=?)`), run.ID, leaseHash, claimRevision, run.ID, claimRevision).Scan(&sent, &projected); err != nil {
		return err
	}
	if sent || projected {
		return ErrStopEvidenceAbsent
	}
	var owner, token string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(run.Scope)).Scan(&owner, &token); err != nil {
		return err
	}
	if owner != run.ID || token != run.LeaseToken {
		return platformruntime.ErrLeaseConflict
	}
	// Unknown provider charges, tools or descendants still block terminal state.
	if s.terminalOutcomeFence == nil {
		return platformruntime.ErrInvalidTransition
	}
	if err := s.checkCancellationFenceTx(ctx, tx, run.Scope); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"source": "platform-undispatched-claim/v1", "protocol_epoch": epoch, "protocol_version": version, "claim_revision": claimRevision, "execution_revision": run.Revision - 1, "lease_token_hash": leaseHash, "request_hash": requestHash, "resume_input_hash": resumeHash})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,?)`), run.ID, "undispatched_cancel_confirmed", payload, time.Now().UTC())
	return err
}
