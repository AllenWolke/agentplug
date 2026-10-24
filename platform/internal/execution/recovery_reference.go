package execution

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"

	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// RecoveryStopReference records the generation whose exit was confirmed by
// the trusted controller. It is provenance, not a checkpoint, execution token,
// or authority to invoke an Agent. Original approval input remains separate.
type RecoveryStopReference struct {
	Version         string                                   `json:"version"`
	RunID           string                                   `json:"run_id"`
	StoppedRevision uint64                                   `json:"stopped_revision"`
	ReadyRevision   uint64                                   `json:"ready_revision"`
	Operation       string                                   `json:"operation"`
	BodyHash        string                                   `json:"body_hash"`
	PolicyHash      string                                   `json:"policy_hash"`
	LeaseHash       string                                   `json:"lease_token_hash"`
	RequestHash     string                                   `json:"request_hash"`
	ResumeInputHash string                                   `json:"resume_input_hash"`
	Source          string                                   `json:"source"`
	ProofDigest     string                                   `json:"proof_digest,omitempty"`
	RuntimeID       string                                   `json:"runtime_id,omitempty"`
	Checkpoints     []contract.RecoveryCheckpointReference   `json:"checkpoints,omitempty"`
	CheckpointSet   *contract.RecoveryCheckpointSetReference `json:"checkpoint_set,omitempty"`
}

func validRecoveryDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func (r RecoveryStopReference) valid() bool {
	if (r.Version != "runtime-recovery-stop/v1" && r.Version != "runtime-recovery-stop/v2") || r.RunID == "" || len(r.RunID) > 128 || r.StoppedRevision == 0 || r.StoppedRevision >= (1<<53)-2 || r.ReadyRevision != r.StoppedRevision+2 {
		return false
	}
	if r.Operation != "invoke" && r.Operation != "run" && r.Operation != "resume" {
		return false
	}
	for _, value := range []string{r.BodyHash, r.PolicyHash, r.LeaseHash, r.RequestHash, r.ResumeInputHash} {
		if !validRecoveryDigest(value) {
			return false
		}
	}
	if r.Version == "runtime-recovery-stop/v1" {
		if r.CheckpointSet != nil || len(r.Checkpoints) > contract.MaxRecoveryCheckpoints {
			return false
		}
	} else {
		if r.CheckpointSet == nil || r.CheckpointSet.Validate() != nil {
			return false
		}
		if len(r.Checkpoints) != 0 {
			set, err := contract.RecoveryCheckpointSet(r.Checkpoints)
			if err != nil || set != *r.CheckpointSet {
				return false
			}
		}
	}
	previousKey := ""
	for _, checkpoint := range r.Checkpoints {
		if checkpoint.Validate(r.StoppedRevision) != nil || checkpoint.StateKey <= previousKey {
			return false
		}
		previousKey = checkpoint.StateKey
	}
	if r.Source == "runtime-process-stop/v1" {
		return validRecoveryDigest(r.ProofDigest) && validRecoveryDigest(r.RuntimeID)
	}
	return r.Source == "sdk-cancel-exit/v1" && r.ProofDigest == "" && r.RuntimeID == ""
}

func recoveryStopReferenceTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, proof *StopEvidence) (RecoveryStopReference, error) {
	if tx == nil || run.Status != platformruntime.StatusRecovering || run.Revision < 2 || run.LeaseToken == "" || len(run.RequestJSON) == 0 || len(run.RequestJSON) > 1<<20 || len(run.ResumeInputJSON) > 1<<20 || run.AgentEndpoint == "" {
		return RecoveryStopReference{}, platformruntime.ErrInvalidTransition
	}
	// The caller already owns Run UPDATE. Read the actual old dispatch before
	// the session lock; the next dispatch overwrites this per-Run projection.
	var command platformruntime.DispatchCommand
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,revision,operation,body_hash,policy_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), run.ID).Scan(&command.RunID, &command.Revision, &command.Operation, &command.BodyHash, &command.PolicyHash)
	if err != nil {
		return RecoveryStopReference{}, err
	}
	if command.Validate() != nil || command.RunID != run.ID || command.Revision != run.Revision-1 {
		return RecoveryStopReference{}, platformruntime.ErrRevisionConflict
	}
	var original contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &original) != nil || original.Scope.RunID != run.ID {
		return RecoveryStopReference{}, platformruntime.ErrInvalidRequest
	}
	policy, ok := original.Input["policy_snapshot"].(map[string]any)
	if !ok || policy["content_hash"] != command.PolicyHash {
		return RecoveryStopReference{}, platformruntime.ErrInvalidRequest
	}
	ref := RecoveryStopReference{Version: "runtime-recovery-stop/v1", RunID: run.ID, StoppedRevision: command.Revision, ReadyRevision: run.Revision + 1,
		Operation: command.Operation, BodyHash: command.BodyHash, PolicyHash: command.PolicyHash,
		LeaseHash: stopHash([]byte(run.LeaseToken)), RequestHash: stopHash(run.RequestJSON), ResumeInputHash: stopHash(run.ResumeInputJSON), Source: "sdk-cancel-exit/v1"}
	if proof != nil {
		ref.Source, ref.ProofDigest, ref.RuntimeID = proof.Source, proof.Digest, proof.RuntimeID
	}
	if !ref.valid() {
		return RecoveryStopReference{}, platformruntime.ErrInvalidRequest
	}
	return ref, nil
}
