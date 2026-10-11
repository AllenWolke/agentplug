package execution

import (
	"context"
	"database/sql"
	"encoding/json"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Internal task exit is proven by the synchronous owner's durable receipt,
// not by an external SDK dispatch or container-stop assertion.
type internalRecoveryStopReference struct {
	Version         string `json:"version"`
	RunID           string `json:"run_id"`
	StoppedRevision uint64 `json:"stopped_revision"`
	ReadyRevision   uint64 `json:"ready_revision"`
	RequestHash     string `json:"request_hash"`
	ResumeInputHash string `json:"resume_input_hash"`
	LeaseHash       string `json:"lease_token_hash"`
	ReceiptHash     string `json:"receipt_hash"`
	Source          string `json:"source"`
}

func internalRecoveryReferenceTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) (internalRecoveryStopReference, error) {
	if tx == nil || !internalIndexOwner(run, run.Scope) || run.Status != platformruntime.StatusRecovering || run.LeaseToken == "" || run.Revision < 2 || run.Revision >= (1<<53)-1 {
		return internalRecoveryStopReference{}, platformruntime.ErrInvalidTransition
	}
	receipt := internalStopReceipt{ExecutionRevision: run.Revision - 1, LeaseDigest: stopHash([]byte(run.LeaseToken))}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return internalRecoveryStopReference{}, err
	}
	var present bool
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_event WHERE run_id=? AND event_type='internal_task_stopped' AND payload::jsonb=?::jsonb)`), run.ID, raw).Scan(&present); err != nil {
		return internalRecoveryStopReference{}, err
	}
	if !present {
		return internalRecoveryStopReference{}, ErrStopEvidenceAbsent
	}
	return internalRecoveryStopReference{Version: "internal-task-recovery-stop/v1", RunID: run.ID, StoppedRevision: receipt.ExecutionRevision, ReadyRevision: run.Revision + 1,
		RequestHash: stopHash(run.RequestJSON), ResumeInputHash: stopHash(run.ResumeInputJSON), LeaseHash: receipt.LeaseDigest, ReceiptHash: stopHash(raw), Source: "internal-task-stopped/v1"}, nil
}
