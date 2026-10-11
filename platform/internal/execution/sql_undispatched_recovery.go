package execution

import (
	"context"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// TryRecoverUndispatched permits only the first, positively journalled claim
// under the protocol that persists every outbound command before transport.
// Old/unknown generations never gain permission from an absent dispatch row.
func (s *SQLStore) TryRecoverUndispatched(ctx context.Context, id string, expected uint64) (bool, error) {
	if ctx == nil || s == nil || s.db == nil || id == "" {
		return false, platformruntime.ErrInvalidRequest
	}
	if expected != 4 {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	run, err := readExecutionRun(ctx, tx, id, " FOR UPDATE")
	if err != nil {
		return false, err
	}
	if run.Status != platformruntime.StatusRecovering || run.Revision != expected {
		return false, platformruntime.ErrRevisionConflict
	}
	if run.AgentEndpoint == "" || run.LeaseToken == "" || len(run.ResumeInputJSON) != 0 || run.Scope.ValidateTrusted() != nil {
		return false, nil
	}
	var request contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &request) != nil || (request.Operation != "invoke" && request.Operation != "run") ||
		request.ResumeInput != nil || request.Scope.RunID != run.ID || request.IdempotencyKey != run.IdempotencyKey {
		return false, nil
	}
	scope := run.Scope
	expectedScope := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID,
		ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID,
		AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID,
		SessionID: scope.SessionID, RunID: scope.RunID, InstallationID: scope.InstallationID,
		AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID,
		DelegationDepth: request.Scope.DelegationDepth}
	if request.Scope != expectedScope || request.Scope.DelegationDepth > 4 ||
		(scope.ParentRunID == "" && request.Scope.DelegationDepth != 0) ||
		(scope.ParentRunID != "" && request.Scope.DelegationDepth == 0) {
		return false, nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_execution_generation_claim_journal WHERE run_id=?`), id).Scan(&count); err != nil {
		return false, err
	}
	if count != 1 {
		return false, nil
	}
	var epoch int
	var version, priorStatus, leaseHash, requestHash, resumeHash string
	var priorRevision, claimRevision uint64
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT protocol_epoch,protocol_version,prior_status,prior_revision,claim_revision,lease_token_hash,request_hash,resume_input_hash
 FROM platform_execution_generation_claim_journal WHERE run_id=? FOR SHARE`), id).
		Scan(&epoch, &version, &priorStatus, &priorRevision, &claimRevision, &leaseHash, &requestHash, &resumeHash); err != nil {
		return false, err
	}
	if epoch != generationJournalProtocolEpoch || version != generationJournalProtocolVersion || priorStatus != "accepted" ||
		priorRevision != 1 || claimRevision != 2 || leaseHash != generationJournalHash([]byte(run.LeaseToken)) ||
		requestHash != generationJournalHash(run.RequestJSON) || resumeHash != generationJournalHash(run.ResumeInputJSON) {
		return false, nil
	}
	var dispatched, projected, outcome bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT
 EXISTS(SELECT 1 FROM platform_execution_generation_dispatch_journal WHERE run_id=?),
 EXISTS(SELECT 1 FROM platform_execution_dispatch_command WHERE run_id=?),
 EXISTS(SELECT 1 FROM platform_execution_outcome WHERE run_id=?)`), id, id, id).
		Scan(&dispatched, &projected, &outcome); err != nil {
		return false, err
	}
	if dispatched || projected || outcome {
		return false, nil
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return false, err
	}
	if run.LeaseUntil.After(now) {
		return false, platformruntime.ErrLeaseConflict
	}
	var owner, token string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(run.Scope)).Scan(&owner, &token); err != nil {
		return false, err
	}
	if owner != run.ID || token != run.LeaseToken {
		return false, platformruntime.ErrLeaseConflict
	}
	if s.recoveryDescendants != nil {
		if err := s.recoveryDescendants(ctx, tx, run.Scope); err != nil {
			return false, err
		}
	}
	if s.recoverySettlement == nil {
		return false, platformruntime.ErrInvalidTransition
	}
	if err := s.recoverySettlement(ctx, run.Scope); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET status='running',revision=revision+1,lease_token='',lease_until=NULL,updated_at=?
 WHERE run_id=? AND status='recovering' AND revision=? AND lease_token=?`), now, id, expected, run.LeaseToken)
	if err != nil {
		return false, err
	}
	if count, err := result.RowsAffected(); err != nil {
		return false, err
	} else if count != 1 {
		return false, platformruntime.ErrRevisionConflict
	}
	result, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_session_lease SET lease_token='',lease_until=NULL WHERE session_key=? AND run_id=? AND lease_token=?`),
		platformruntime.SessionExecutionKey(run.Scope), id, run.LeaseToken)
	if err != nil {
		return false, err
	}
	if count, err := result.RowsAffected(); err != nil {
		return false, err
	} else if count != 1 {
		return false, platformruntime.ErrLeaseConflict
	}
	payload, err := json.Marshal(map[string]any{"revision": expected + 1, "protocol_epoch": epoch, "protocol_version": version,
		"claim_revision": claimRevision, "execution_revision": expected - 1, "code": "INITIAL_GENERATION_NOT_DISPATCHED"})
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES (?,?,?,?)`),
		id, "undispatched_requeued", payload, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
