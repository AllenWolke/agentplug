package execution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func decodeWaitingHandoff(payload map[string]any) (contract.HandlerHandoff, error) {
	var receipt contract.HandlerHandoff
	if payload["source"] != "platform_agent_gateway" || payload["handoff"] == nil {
		return receipt, platformruntime.ErrInvalidTransition
	}
	raw, err := json.Marshal(payload["handoff"])
	if err != nil || len(raw) > 4096 {
		return receipt, platformruntime.ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF {
		return contract.HandlerHandoff{}, platformruntime.ErrInvalidRequest
	}
	return receipt, nil
}

// validateWaitingHandoffTx runs under the existing Run UPDATE and live session
// lease fences. The receipt, waiting status, outcome and event then commit in
// the same transition transaction; no separate acknowledgement can race them.
func validateWaitingHandoffTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, outcome *platformruntime.Outcome) error {
	if outcome == nil || outcome.EventPayload["handoff"] == nil {
		return nil // A legacy waiting result never establishes a handoff.
	}
	if outcome.EventType != "waiting" {
		return platformruntime.ErrInvalidTransition
	}
	receipt, err := decodeWaitingHandoff(outcome.EventPayload)
	if err != nil {
		return err
	}
	var revision uint64
	var bodyHash string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,body_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), run.ID).Scan(&revision, &bodyHash) != nil || revision != run.Revision || receipt.Validate(run.ID, revision, bodyHash, run.LeaseToken) != nil {
		return platformruntime.ErrLeaseConflict
	}
	return nil
}

// WaitingHandlerHandoffTx returns only a receipt previously committed by the
// signed production dispatcher. Callers own current IAM/ancestor/checkpoint
// fences and must validate the pending operation before creating a resume.
// Missing proof is denied; waiting status and lease expiry are never fallback
// evidence. This read issues no lease, signature, execution or budget release.
func (s *SQLStore) WaitingHandlerHandoffTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, expected uint64) (contract.HandlerHandoff, error) {
	var receipt contract.HandlerHandoff
	if s == nil || s.db == nil || tx == nil || scope.ValidateTrusted() != nil || expected < 2 || expected >= 1<<53 || ctx.Err() != nil {
		return receipt, platformruntime.ErrInvalidRequest
	}
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, scope.RunID)
	if err != nil || facts.Scope != scope || facts.Status != platformruntime.StatusWaiting || facts.Revision != expected {
		return receipt, platformruntime.ErrRevisionConflict
	}
	var oldLease string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token FROM platform_execution_run WHERE run_id=?`), scope.RunID).Scan(&oldLease) != nil || oldLease == "" {
		return receipt, platformruntime.ErrLeaseConflict
	}
	return persistedWaitingHandoffTx(ctx, tx, scope.RunID, expected, oldLease)
}

// The caller holds the current Run UPDATE fence. The waiting outcome must
// still refer to this exact historical execution command and lease.
func persistedWaitingHandoffTx(ctx context.Context, tx *sql.Tx, runID string, expected uint64, oldLease string) (contract.HandlerHandoff, error) {
	var receipt contract.HandlerHandoff
	var revision uint64
	var eventType string
	var raw []byte
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type,event_payload FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), runID).Scan(&revision, &eventType, &raw) != nil || revision != expected || eventType != "waiting" || len(raw) > 8192 {
		return receipt, platformruntime.ErrInvalidTransition
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return receipt, platformruntime.ErrInvalidRequest
	}
	receipt, err := decodeWaitingHandoff(payload)
	if err != nil {
		return contract.HandlerHandoff{}, err
	}
	var commandRevision uint64
	var bodyHash string
	if tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,body_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), runID).Scan(&commandRevision, &bodyHash) != nil || commandRevision != expected-1 || receipt.Validate(runID, expected-1, bodyHash, oldLease) != nil {
		return contract.HandlerHandoff{}, platformruntime.ErrLeaseConflict
	}
	return receipt, nil
}

// CancellationWaitingHandoff is a read-only stop-control probe, not business
// admission. The final cancellation transaction revalidates the same receipt.
func (s *SQLStore) CancellationWaitingHandoff(ctx context.Context, pending platformruntime.Run) (contract.HandlerHandoff, error) {
	var receipt contract.HandlerHandoff
	if pending.Status != platformruntime.StatusCancelling || pending.Revision < 3 || pending.LeaseToken == "" {
		return receipt, ErrStopEvidenceAbsent
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer tx.Rollback()
	facts, err := s.BudgetRunForUpdateTx(ctx, tx, pending.ID)
	if err != nil {
		return receipt, err
	}
	if facts.Scope != pending.Scope || facts.Status != pending.Status || facts.Revision != pending.Revision {
		return receipt, platformruntime.ErrRevisionConflict
	}
	var revision uint64
	var eventType string
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,event_type FROM platform_execution_outcome WHERE run_id=? FOR SHARE`), pending.ID).Scan(&revision, &eventType)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (revision != pending.Revision-1 || eventType != "waiting")) {
		return receipt, ErrStopEvidenceAbsent
	}
	if err != nil {
		return receipt, err
	}
	var oldLease string
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT lease_token FROM platform_execution_run WHERE run_id=?`), pending.ID).Scan(&oldLease); err != nil {
		return receipt, err
	}
	if oldLease != pending.LeaseToken {
		return receipt, platformruntime.ErrLeaseConflict
	}
	// Legacy waiting has no supervised receipt and must keep the original
	// remote/controller stop path. Invalid committed receipts fail closed.
	var raw []byte
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT event_payload FROM platform_execution_outcome WHERE run_id=?`), pending.ID).Scan(&raw); err != nil {
		return receipt, err
	}
	var payload map[string]any
	if len(raw) > 128<<10 || json.Unmarshal(raw, &payload) != nil {
		return receipt, platformruntime.ErrInvalidRequest
	}
	if payload["handoff"] == nil {
		return receipt, ErrStopEvidenceAbsent
	}
	if len(raw) > 8192 {
		return receipt, platformruntime.ErrInvalidRequest
	}
	return persistedWaitingHandoffTx(ctx, tx, pending.ID, pending.Revision-1, oldLease)
}
