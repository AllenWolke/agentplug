package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Install only the production Evaluation provenance verifier. A terminal
// business Run, a guessed parent ID or a fresh grant is not inverse authority.
// The verifier locks the real cancelling product parent BEFORE this case Run.
func (s *SQLStore) SetCompletedEvaluationCompensationAuthority(check func(context.Context, *sql.Tx, platformruntime.Run) error) error {
	if s == nil || check == nil || s.completedEvaluationControl != nil || s.cancellationSaga != nil {
		return compensation.ErrUnavailable
	}
	s.completedEvaluationControl = check
	return nil
}

func completedEvaluationStatus(status platformruntime.Status) bool {
	return status == platformruntime.StatusSucceeded || status == platformruntime.StatusFailed
}

// Derive evidence from an existing terminal outcome, never from a caller's
// acknowledgement. Retain the original status, revision, output and charges.
// ConfirmStopped additionally checks complete tree/effect settlement.
func (s *SQLStore) completedEvaluationStopProofTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) (compensation.StopProof, error) {
	if s.completedEvaluationControl == nil || !completedEvaluationStatus(run.Status) || run.Scope.ParentRunID == "" || run.LeaseToken != "" || !run.LeaseUntil.IsZero() || run.Revision == 0 {
		return compensation.StopProof{}, compensation.ErrPending
	}
	var revision uint64
	var output, payload []byte
	var event string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,output_json,event_type,event_payload FROM platform_execution_outcome WHERE run_id=?`), run.ID).Scan(&revision, &output, &event, &payload); err != nil {
		return compensation.StopProof{}, err
	}
	expected := "task_completed"
	if run.Status == platformruntime.StatusFailed {
		expected = "task_failed"
	}
	if revision != run.Revision || event != expected || !json.Valid(output) || !json.Valid(payload) {
		return compensation.StopProof{}, compensation.ErrConflict
	}
	evidence, _ := json.Marshal(struct {
		Version, ScopeDigest, RequestDigest, OutputDigest, Event, PayloadDigest string
		Revision                                                                uint64
	}{"completed-evaluation-stop/v1", compensation.ScopeDigest(run.Scope), stopHash(run.RequestJSON), stopHash(output), event, stopHash(payload), revision})
	return compensation.StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: compensation.ScopeDigest(run.Scope), Revision: revision, EvidenceDigest: stopHash(evidence)}, nil
}

// RequestCompletedEvaluationCompensation controls only already registered
// effects of a completed case whose real product parent has been cancelled.
// It never reopens the case, replays forward operations or changes its outcome.
func (s *SQLStore) RequestCompletedEvaluationCompensation(ctx context.Context, scope sharedkernel.Scope) error {
	if s == nil || s.cancellationSaga == nil || scope.ValidateTrusted() != nil || scope.ParentRunID == "" {
		return compensation.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	authority := cancellationAuthority{runs: s, ports: s.cancellationPorts}
	run, err := authority.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if !completedEvaluationStatus(run.Status) {
		return compensation.ErrPending
	}
	proof, err := s.completedEvaluationStopProofTx(ctx, tx, run)
	if err != nil {
		return err
	}
	progress, found, err := s.cancellationSaga.ProgressTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if found && progress.Phase == "complete" {
		return tx.Commit()
	}
	if err := s.terminalOutcomeFence(ctx, tx, scope); err != nil {
		return err
	}
	if _, err = s.cancellationSaga.BeginTx(ctx, tx, scope, run.Revision); err != nil {
		return err
	}
	if s.cancellationPorts.PrepareCoverageTx != nil {
		if err = s.cancellationPorts.PrepareCoverageTx(ctx, tx, scope, s.cancellationSaga); err != nil {
			return err
		}
	}
	if err = s.cancellationSaga.ConfirmStoppedTx(ctx, tx, scope, proof); err != nil {
		return err
	}
	if err = s.cancellationSaga.FinalizeTx(ctx, tx, scope); err != nil && !errors.Is(err, compensation.ErrPending) {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CompletedEvaluationCompensationComplete(ctx context.Context, scope sharedkernel.Scope) (bool, error) {
	if s == nil || s.cancellationSaga == nil || s.completedEvaluationControl == nil {
		return false, compensation.ErrUnavailable
	}
	progress, found, err := s.cancellationSaga.Progress(ctx, scope)
	return err == nil && found && progress.Phase == "complete" && progress.StopConfirmed && progress.Unresolved == 0 && progress.Attention == 0, err
}
