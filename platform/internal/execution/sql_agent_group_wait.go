package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type AgentGroupWaitReference struct {
	Version         string                                 `json:"version"`
	OriginOperation string                                 `json:"origin_operation"`
	WaitingRevision uint64                                 `json:"waiting_revision"`
	Handoff         contract.AgentGroupHandoff             `json:"handoff"`
	Checkpoints     []contract.RecoveryCheckpointReference `json:"checkpoints"`
}

// CancellationAgentGroupHandoff probes historical exit only. Checkpoint
// expiry/revocation do not prevent stopping; final cancellation independently
// repeats the committed receipt and real child/model stop barriers.
func (s *SQLStore) CancellationAgentGroupHandoff(ctx context.Context, pending platformruntime.Run) (contract.AgentGroupHandoff, error) {
	var empty contract.AgentGroupHandoff
	if s == nil || s.db == nil || pending.Status != platformruntime.StatusCancelling || pending.Revision < 3 || pending.LeaseToken == "" {
		return empty, ErrStopEvidenceAbsent
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, pending.ID)
	if err != nil {
		return empty, err
	}
	if facts.Scope != pending.Scope || facts.Status != pending.Status || facts.Revision != pending.Revision {
		return empty, platformruntime.ErrRevisionConflict
	}
	var revision uint64
	var eventType string
	var raw []byte
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,event_payload FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), pending.ID).Scan(&revision, &eventType, &raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (revision != pending.Revision-1 || eventType != "waiting")) {
		return empty, ErrStopEvidenceAbsent
	}
	if err != nil {
		return empty, err
	}
	var payload map[string]json.RawMessage
	if len(raw) > 128<<10 || json.Unmarshal(raw, &payload) != nil {
		return empty, platformruntime.ErrInvalidRequest
	}
	if payload["agent_group_handoff"] == nil {
		return empty, ErrStopEvidenceAbsent
	}
	var lease string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token FROM platform_execution_run WHERE run_id=?`), pending.ID).Scan(&lease) != nil || lease != pending.LeaseToken {
		return empty, platformruntime.ErrLeaseConflict
	}
	ref, err := s.AgentGroupWaitReferenceTx(ctx, tx, pending.ID, pending.Revision-1, lease)
	if err != nil {
		return empty, err
	}
	return ref.Handoff, nil
}

// BeginAgentGroupWaitCancellationTx records bounded system stop intent after
// verifying the old handler exit. It issues no credentials and does not mark
// cancellation complete or release any budget/model/session reservation.
func (s *SQLStore) BeginAgentGroupWaitCancellationTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, expected uint64, reason string) (platformruntime.Run, error) {
	if reason != "GROUP_AUTHORIZATION_DENIED" && reason != "GROUP_STATE_CONTINUITY_LOST" {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	run, err := readExecutionRun(ctx, tx, scope.RunID, " FOR UPDATE")
	if err != nil {
		return platformruntime.Run{}, err
	}
	if run.Scope != scope || run.Status != platformruntime.StatusWaiting || run.Revision != expected {
		return platformruntime.Run{}, platformruntime.ErrRevisionConflict
	}
	if _, err := s.AgentGroupWaitReferenceTx(ctx, tx, run.ID, expected, run.LeaseToken); err != nil {
		return platformruntime.Run{}, err
	}
	return s.beginCancellationTx(ctx, tx, run, reason)
}

// CurrentAgentGroupWaitTx verifies the committed waiting generation and all
// current State references. The caller still owns IAM, exact child lineage and
// policy checks; this port issues no lease and grants no parent execution.
func (s *SQLStore) CurrentAgentGroupWaitTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (AgentGroupWaitReference, error) {
	var empty AgentGroupWaitReference
	if s == nil || s.groupWaitCheckpoint == nil || scope.ValidateTrusted() != nil {
		return empty, platformruntime.ErrInvalidRequest
	}
	facts, err := s.BudgetRunTx(ctx, tx, scope.RunID)
	if err != nil {
		return empty, err
	}
	if facts.Scope != scope || facts.Status != platformruntime.StatusWaiting {
		return empty, platformruntime.ErrInvalidTransition
	}
	var lease string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token FROM platform_execution_run WHERE run_id=?`), scope.RunID).Scan(&lease); err != nil {
		return empty, err
	}
	ref, err := s.AgentGroupWaitReferenceTx(ctx, tx, scope.RunID, facts.Revision, lease)
	if err != nil {
		return empty, err
	}
	current, err := s.groupWaitCheckpoint(ctx, tx, scope, ref.Handoff)
	if err != nil {
		return empty, err
	}
	if len(current) != len(ref.Checkpoints) {
		return empty, platformruntime.ErrInvalidTransition
	}
	for i, cp := range current {
		old := ref.Checkpoints[i]
		if cp.StateKey != old.StateKey || cp.Revision != old.Revision || cp.SchemaID != old.SchemaID || cp.ContentHash != old.ContentHash || cp.ExecutionRevision != old.ExecutionRevision || !cp.ExpiresAt.Equal(old.ExpiresAt) {
			return empty, platformruntime.ErrInvalidTransition
		}
	}
	return ref, nil
}

// event_payload is JSON. strpos has no json overload; cast before searching.
// A failed scan leaves a waiting parent parked with no wake candidate.
const agentGroupWaitingCandidateSQL = `SELECT r.run_id FROM platform_execution_run r JOIN platform_execution_outcome o ON o.run_id=r.run_id AND o.revision=r.revision WHERE r.status='waiting' AND o.event_type='waiting' AND strpos(o.event_payload::text,'"group_wait_reference"')>0 AND r.run_id>? ORDER BY r.run_id LIMIT ?`

func (s *SQLStore) AgentGroupWaitingCandidates(ctx context.Context, after string, limit int) ([]string, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 256 {
		return nil, platformruntime.ErrInvalidRequest
	}
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(agentGroupWaitingCandidateSQL), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// QueueAgentGroupResumeTx requires caller-owned root-first Run UPDATE, current
// IAM/delegation/target authority and proven real terminal children. It
// revalidates State/provenance, parks a durable signed-dispatch input and grants
// no lease or capability. The ordinary worker must later claim a new lease.
func (s *SQLStore) QueueAgentGroupResumeTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, expected uint64) (uint64, error) {
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
	if err != nil {
		return 0, err
	}
	if facts.Scope != scope || facts.Status != platformruntime.StatusWaiting || facts.Revision != expected {
		return 0, platformruntime.ErrRevisionConflict
	}
	ref, err := s.CurrentAgentGroupWaitTx(ctx, tx, scope)
	if err != nil {
		return 0, err
	}
	if s.groupStopBarrier == nil || s.groupResumeQuiescence == nil {
		return 0, platformruntime.ErrInvalidTransition
	}
	if err := s.groupStopBarrier(ctx, tx, scope, ref.Handoff); err != nil {
		return 0, err
	}
	if err := s.groupResumeQuiescence(ctx, scope); err != nil {
		return 0, err
	}
	input, err := json.Marshal(ref)
	if err != nil || len(input) > 128<<10 {
		return 0, platformruntime.ErrInvalidRequest
	}
	var sessionRun, sessionToken string
	var sessionUntil sql.NullTime
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,lease_token,lease_until FROM platform_execution_session_lease WHERE session_key=? FOR UPDATE`), platformruntime.SessionExecutionKey(scope)).Scan(&sessionRun, &sessionToken, &sessionUntil) != nil || sessionRun != scope.RunID || sessionToken != "" || sessionUntil.Valid {
		return 0, platformruntime.ErrLeaseConflict
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_execution_run SET resume_input_json=?,status='running',revision=revision+1,updated_at=clock_timestamp(),lease_token='',lease_until=NULL WHERE run_id=? AND status='waiting' AND revision=?`), input, scope.RunID, expected)
	if err != nil {
		return 0, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return 0, platformruntime.ErrRevisionConflict
	}
	payload, err := json.Marshal(map[string]any{"from": "waiting", "to": "running", "revision": expected + 1, "reason": "agent_group_terminal"})
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,clock_timestamp())`), scope.RunID, "status", payload); err != nil {
		return 0, err
	}
	return expected + 1, nil
}

// AgentGroupWaitReferenceTx reads an already committed exact execution-exit
// proof under the caller's Run fence. It is not authorization to resume, retain
// children or disclose results: callers must additionally check current State,
// routing, IAM and budgets. Expired State does not erase historical exit proof.
func (s *SQLStore) AgentGroupWaitReferenceTx(ctx context.Context, tx *sql.Tx, runID string, waitingRevision uint64, oldLease string) (AgentGroupWaitReference, error) {
	var ref AgentGroupWaitReference
	if s == nil || tx == nil || ctx == nil || ctx.Err() != nil || waitingRevision < 2 || oldLease == "" {
		return ref, platformruntime.ErrInvalidRequest
	}
	var revision uint64
	var eventType string
	var raw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,event_payload FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), runID).Scan(&revision, &eventType, &raw); err != nil {
		return ref, err
	}
	if revision != waitingRevision || eventType != "waiting" || len(raw) > 128<<10 {
		return ref, platformruntime.ErrInvalidTransition
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil || !bytes.Equal(payload["source"], []byte(`"platform_agent_gateway"`)) || payload["handoff"] != nil || payload["agent_group_handoff"] == nil || payload["group_wait_reference"] == nil {
		return ref, platformruntime.ErrInvalidTransition
	}
	if strictStopJSON(payload["group_wait_reference"], &ref) != nil || ref.Version != "agent-group-resume/v1" || ref.WaitingRevision != waitingRevision || ref.Handoff.ExecutionRevision != waitingRevision-1 || ref.OriginOperation != ref.Handoff.OriginOperation || len(ref.Checkpoints) < 1 || len(ref.Checkpoints) > contract.MaxRecoveryCheckpoints {
		return AgentGroupWaitReference{}, platformruntime.ErrInvalidRequest
	}
	var receipt contract.AgentGroupHandoff
	if strictStopJSON(payload["agent_group_handoff"], &receipt) != nil {
		return AgentGroupWaitReference{}, platformruntime.ErrInvalidRequest
	}
	a, _ := json.Marshal(receipt)
	b, _ := json.Marshal(ref.Handoff)
	if !bytes.Equal(a, b) {
		return AgentGroupWaitReference{}, platformruntime.ErrInvalidRequest
	}
	var commandRevision uint64
	var bodyHash string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,body_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), runID).Scan(&commandRevision, &bodyHash) != nil || commandRevision != waitingRevision-1 || ref.Handoff.Validate(runID, commandRevision, bodyHash, oldLease) != nil {
		return AgentGroupWaitReference{}, platformruntime.ErrLeaseConflict
	}
	seen := map[string]bool{}
	found := false
	for _, cp := range ref.Checkpoints {
		if cp.Validate(commandRevision) != nil || seen[cp.StateKey] {
			return AgentGroupWaitReference{}, platformruntime.ErrInvalidRequest
		}
		seen[cp.StateKey] = true
		h := ref.Handoff.Checkpoint
		if cp.StateKey == h.StateKey && cp.Revision == h.Revision && cp.SchemaID == h.SchemaID && cp.ContentHash == h.ContentHash && cp.ExecutionRevision == h.ExecutionRevision && cp.ExpiresAt.Equal(h.ExpiresAt) {
			found = true
		}
	}
	if !found {
		return AgentGroupWaitReference{}, platformruntime.ErrInvalidRequest
	}
	return ref, nil
}

func (s *SQLStore) validateGroupWaitingTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, outcome *platformruntime.Outcome) error {
	if outcome == nil || outcome.EventPayload["agent_group_handoff"] == nil {
		return nil
	}
	if outcome.EventType != "waiting" || outcome.EventPayload["source"] != "platform_agent_gateway" || outcome.EventPayload["handoff"] != nil || s.groupWaitCheckpoint == nil || s.groupWaitPlan == nil {
		return platformruntime.ErrInvalidTransition
	}
	raw, err := json.Marshal(outcome.EventPayload["agent_group_handoff"])
	if err != nil || len(raw) > 8192 {
		return platformruntime.ErrInvalidRequest
	}
	var receipt contract.AgentGroupHandoff
	if strictStopJSON(raw, &receipt) != nil {
		return platformruntime.ErrInvalidRequest
	}
	var revision uint64
	var bodyHash string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,body_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), run.ID).Scan(&revision, &bodyHash) != nil || revision != run.Revision || receipt.Validate(run.ID, revision, bodyHash, run.LeaseToken) != nil {
		return platformruntime.ErrLeaseConflict
	}
	if err := s.groupWaitPlan(ctx, tx, run.Scope, receipt); err != nil {
		return err
	}
	refs, err := s.groupWaitCheckpoint(ctx, tx, run.Scope, receipt)
	if err != nil {
		return err
	}
	if len(refs) < 1 || len(refs) > contract.MaxRecoveryCheckpoints {
		return platformruntime.ErrInvalidRequest
	}
	outcome.EventPayload["group_wait_reference"] = AgentGroupWaitReference{
		Version: "agent-group-resume/v1", OriginOperation: receipt.OriginOperation,
		WaitingRevision: run.Revision + 1, Handoff: receipt, Checkpoints: refs,
	}
	return nil
}
