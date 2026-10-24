package execution

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// ApprovedToolResume contains only the identifiers and digests of the approval.
// It deliberately has no token, password, tool arguments or business input.
type ApprovedToolResume struct {
	Version         string                   `json:"version"`
	WaitingRevision uint64                   `json:"waiting_revision"`
	Claims          ApprovedToolResumeClaims `json:"claims"`
	Handoff         contract.HandlerHandoff  `json:"handoff"`
	CheckpointHash  string                   `json:"checkpoint_hash"`
	PreviousReview  *CommittedBusinessReview `json:"previous_review,omitempty"`
}

// CommittedBusinessReview preserves a browser decision across later tool
// approvals. Only the locked repository copies it from committed Run input.
type CommittedBusinessReview struct {
	Reviewer string `json:"reviewer_id"`
	Decision string `json:"decision"`
}

func (r CommittedBusinessReview) valid(scope sharedkernel.Scope) bool {
	return r.Reviewer != "" && len(r.Reviewer) <= 128 && r.Reviewer != scope.PrincipalID && (r.Decision == "approve" || r.Decision == "reject" || r.Decision == "request_changes")
}

func committedBusinessReview(input []byte, scope sharedkernel.Scope) *CommittedBusinessReview {
	if len(input) == 0 || len(input) > 1<<16 {
		return nil
	}
	var marker struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(input, &marker) != nil {
		return nil
	}
	if marker.Version == "harness-tool-resume/v1" {
		var previous ApprovedToolResume
		if json.Unmarshal(input, &previous) != nil || !previous.valid(scope) || previous.PreviousReview == nil {
			return nil
		}
		copy := *previous.PreviousReview
		return &copy
	}
	if marker.Version != "" {
		return nil
	}
	var review CommittedBusinessReview
	if json.Unmarshal(input, &review) != nil || !review.valid(scope) {
		return nil
	}
	return &review
}

type ApprovedToolResumeClaims struct {
	Version            string `json:"version"`
	ApprovalID         string `json:"approval_id"`
	ActorID            string `json:"actor_id"`
	ScopeHash          string `json:"scope_hash"`
	AuthorizationEpoch uint64 `json:"authorization_epoch"`
	PolicyHash         string `json:"policy_hash"`
	ToolName           string `json:"tool_name"`
	CallID             string `json:"call_id"`
	Fingerprint        string `json:"fingerprint"`
	IssuedAt           int64  `json:"issued_at"`
	ExpiresAt          int64  `json:"expires_at"`
	PendingKey         string `json:"pending_key"`
	CheckpointRevision uint64 `json:"checkpoint_revision"`
}

func (r ApprovedToolResume) valid(scope sharedkernel.Scope) bool {
	c := r.Claims
	if r.PreviousReview != nil && !r.PreviousReview.valid(scope) {
		return false
	}
	if r.Version != "harness-tool-resume/v1" || r.WaitingRevision < 2 || r.WaitingRevision >= 1<<63-1 || c.Version != "tool-confirmation/v1" || c.ActorID != scope.PrincipalID || c.AuthorizationEpoch != scope.AuthorizationEpoch || c.IssuedAt <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 300 || c.CheckpointRevision == 0 || c.CheckpointRevision > 64 {
		return false
	}
	for _, name := range []string{c.ApprovalID, c.ActorID, c.ToolName, c.CallID, c.PendingKey} {
		if name == "" || len(name) > 128 {
			return false
		}
	}
	for _, digest := range []string{c.ScopeHash, c.PolicyHash, c.Fingerprint, r.CheckpointHash} {
		value, err := hex.DecodeString(digest)
		if err != nil || len(value) != 32 {
			return false
		}
	}
	return true
}

// PrepareApprovedResumeTx is the owner-control composition's CAS port. The
// caller owns commit/rollback and must hold current IAM, root-to-leaf Run,
// pending checkpoint and committed approval fences, and record Audit/Outbox.
// Acquire the target Run UPDATE fence before checkpoint/approval SHARE reads;
// concurrent controllers must not both acquire SHARE then upgrade that Run.
// Input is a non-secret approved-reference envelope, never a confirmation token.
// This port does not enqueue, issue a lease, execute an Agent or release budget.
func (s *SQLStore) PrepareApprovedResumeTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, expected uint64, reference ApprovedToolResume) (uint64, error) {
	if s == nil || s.db == nil || tx == nil || ctx.Err() != nil || scope.ValidateTrusted() != nil || scope.PrincipalType != "user" || expected == 0 || expected >= 1<<63-1 || reference.WaitingRevision != expected || reference.PreviousReview != nil || !reference.valid(scope) {
		return 0, platformruntime.ErrInvalidRequest
	}
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
	if err != nil {
		return 0, err
	}
	if facts.Scope != scope || facts.Revision != expected {
		return 0, platformruntime.ErrRevisionConflict
	}
	if facts.Status != platformruntime.StatusWaiting {
		return 0, platformruntime.ErrInvalidTransition
	}
	receipt, err := s.WaitingHandlerHandoffTx(ctx, tx, scope, expected)
	if err != nil || receipt.HarnessKey != reference.Claims.PendingKey || receipt.ToolName != reference.Claims.ToolName || receipt.CallID != reference.Claims.CallID {
		return 0, platformruntime.ErrInvalidTransition
	}
	// Only the store reads the committed exit receipt. Caller-provided fields
	// cannot replace it, and it is preserved before the old lease is cleared.
	if reference.Handoff.Version != "" && reference.Handoff != receipt {
		return 0, platformruntime.ErrInvalidRequest
	}
	reference.Handoff = receipt
	// Never accept review authority from the approval caller or Agent. Preserve
	// only the prior committed decision while holding this exact Run UPDATE lock.
	var previousInput []byte
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT resume_input_json FROM platform_execution_run WHERE run_id=?`), scope.RunID).Scan(&previousInput); err != nil {
		return 0, err
	}
	reference.PreviousReview = committedBusinessReview(previousInput, scope)
	input, err := json.Marshal(reference)
	if err != nil || len(input) > 8192 {
		return 0, platformruntime.ErrInvalidRequest
	}
	// Waiting retains the old Run lease token as historical evidence, while
	// releaseSessionTx clears the actual session execution lease. Check that
	// execution reservation, rather than mistaking the old token for activity.
	var sessionRun, sessionToken string
	var sessionUntil sql.NullTime
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token,lease_until FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(scope)).Scan(&sessionRun, &sessionToken, &sessionUntil) != nil || sessionRun != scope.RunID || sessionToken != "" || sessionUntil.Valid {
		return 0, platformruntime.ErrLeaseConflict
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json=?,status=?,revision=revision+1,updated_at=clock_timestamp(),lease_token='',lease_until=NULL WHERE run_id=? AND status=? AND revision=?`), input, platformruntime.StatusRunning, scope.RunID, platformruntime.StatusWaiting, expected)
	if err != nil {
		return 0, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if changed != 1 {
		return 0, platformruntime.ErrRevisionConflict
	}
	payload, err := json.Marshal(map[string]any{"from": string(platformruntime.StatusWaiting), "to": string(platformruntime.StatusRunning), "revision": expected + 1})
	if err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,clock_timestamp())`), scope.RunID, "status", payload); err != nil {
		return 0, err
	}
	return expected + 1, nil
}
