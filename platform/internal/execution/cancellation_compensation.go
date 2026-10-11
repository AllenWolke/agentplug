package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Composition supplies owner-module ports, never a browser-selected handler.
// ValidateCoverageTx checks the complete admitted tree and all write ledgers;
// a missing registration or an unclassified historical effect must deny it.
type CancellationCompensationPorts struct {
	// Locks IAM and ancestors before the effect's own Run, preserving the
	// parent-stop lock order. Startup composition supplies this for live writes.
	GuardForwardTx       func(context.Context, *sql.Tx, compensation.Step) error
	ValidateStepTx       func(context.Context, *sql.Tx, compensation.Step) error
	ValidateCoverageTx   func(context.Context, *sql.Tx, sharedkernel.Scope) error
	ValidateEnrollmentTx func(context.Context, *sql.Tx, sharedkernel.Scope, compensation.Step) error
	// BeginTx creates the stopping job before exact admitted-tree enrollment.
	// The callback must not execute a forward effect or invent a stop proof.
	PrepareCoverageTx func(context.Context, *sql.Tx, sharedkernel.Scope, compensation.Coordinator) error
}

// Cancellation can resolve a registered business effect from its owner receipt
// even when the forward response was lost. Success and recovery still require
// ordinary ledger settlement. The cancellation-only fence must retain model
// charges, descendant proof and exact effect coverage; it never edits UNKNOWN.
func (s *SQLStore) SetCancellationOutcomeFence(check func(context.Context, *sql.Tx, sharedkernel.Scope) error) error {
	if s == nil || check == nil || s.cancellationFence != nil || s.cancellationSaga != nil {
		return compensation.ErrInvalid
	}
	s.cancellationFence = check
	return nil
}

func (s *SQLStore) checkCancellationFenceTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if s.cancellationSaga != nil && s.cancellationFence != nil {
		return s.cancellationFence(ctx, tx, scope)
	}
	if s.terminalOutcomeFence == nil {
		return compensation.ErrUnavailable
	}
	return s.terminalOutcomeFence(ctx, tx, scope)
}

// Installed only with the durable coordinator. Recovery never uses this port.
func (m *Module) SetCancellationStopQuiescence(check func(context.Context, sharedkernel.Scope) error) error {
	if m == nil {
		return compensation.ErrUnavailable
	}
	s, ok := m.store.(*SQLStore)
	if !ok || s.cancellationSaga == nil || check == nil || m.dispatcher == nil || m.dispatcher.cancellationQuiescence != nil {
		return compensation.ErrUnavailable
	}
	m.dispatcher.cancellationQuiescence = check
	return nil
}

// EnableCancellationCompensation is called once, before workers/HTTP start.
// No production rollout may omit either coverage or the settlement barrier.
func (s *SQLStore) EnableCancellationCompensation(ctx context.Context, ports CancellationCompensationPorts) (compensation.Coordinator, error) {
	if s == nil || s.db == nil || ctx == nil || ports.ValidateStepTx == nil || ports.ValidateCoverageTx == nil || s.terminalOutcomeFence == nil || s.cancellationSaga != nil {
		return nil, compensation.ErrUnavailable
	}
	store, err := compensation.OpenCoordinator(ctx, s.db, cancellationAuthority{runs: s, ports: ports})
	if err != nil {
		return nil, err
	}
	s.cancellationPorts, s.cancellationSaga = ports, store
	return store, nil
}

type cancellationAuthority struct {
	runs  *SQLStore
	ports CancellationCompensationPorts
}

func (a cancellationAuthority) EnrollRecordedEffectTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, step compensation.Step) error {
	run, err := a.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if run.Status != platformruntime.StatusCancelling && !completedEvaluationStatus(run.Status) {
		return compensation.ErrPending
	}
	if step.Root == scope {
		return nil
	}
	if a.ports.ValidateEnrollmentTx == nil {
		return compensation.ErrUnavailable
	}
	return a.ports.ValidateEnrollmentTx(ctx, tx, scope, step)
}

func (a cancellationAuthority) rootTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (platformruntime.Run, error) {
	if a.runs == nil || ctx == nil || tx == nil || scope.ValidateTrusted() != nil {
		return platformruntime.Run{}, compensation.ErrInvalid
	}
	// Completed Evaluation cases retain their terminal outcomes. Acquire the
	// real product-parent fence first, just like creation and budget admission.
	observed, err := readExecutionRun(ctx, tx, scope.RunID, "")
	if err != nil {
		return platformruntime.Run{}, err
	}
	if observed.Scope != scope {
		return platformruntime.Run{}, compensation.ErrConflict
	}
	if completedEvaluationStatus(observed.Status) {
		if a.runs.completedEvaluationControl == nil {
			return platformruntime.Run{}, compensation.ErrUnavailable
		}
		if err = a.runs.completedEvaluationControl(ctx, tx, observed); err != nil {
			return platformruntime.Run{}, err
		}
	}
	run, err := readExecutionRun(ctx, tx, scope.RunID, " FOR UPDATE")
	if err != nil {
		return platformruntime.Run{}, err
	}
	if run.Scope != scope || run.Revision != observed.Revision || run.Status != observed.Status {
		return platformruntime.Run{}, compensation.ErrConflict
	}
	return run, nil
}

func (a cancellationAuthority) RegisterEffectTx(ctx context.Context, tx *sql.Tx, step compensation.Step) error {
	if a.ports.GuardForwardTx != nil {
		if err := a.ports.GuardForwardTx(ctx, tx, step); err != nil {
			return err
		}
	}
	run, err := a.rootTx(ctx, tx, step.Root)
	if err != nil {
		return err
	}
	if run.Status != platformruntime.StatusRunning || a.ports.ValidateStepTx == nil {
		return compensation.ErrPending
	}
	// The effect owner still needs the actual signed live execution fence. A
	// compensation registration never creates a new business permission.
	binding, ok := sharedkernel.ExecutionLeaseFromContext(ctx)
	if !ok {
		return platformruntime.ErrLeaseConflict
	}
	if err := a.ports.ValidateStepTx(ctx, tx, step); err != nil {
		return err
	}
	return a.runs.CheckCapabilityLeaseTx(ctx, tx, step.Scope, binding)
}

func (a cancellationAuthority) BeginCancellationTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, revision uint64) error {
	run, err := a.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if (run.Status != platformruntime.StatusCancelling && !completedEvaluationStatus(run.Status)) || run.Revision != revision {
		return compensation.ErrConflict
	}
	return nil
}

type cancellationStopBinding struct {
	Version        string `json:"version"`
	ScopeDigest    string `json:"scope_digest"`
	Revision       uint64 `json:"revision"`
	Source         string `json:"source"`
	LeaseHash      string `json:"lease_hash"`
	RequestHash    string `json:"request_hash"`
	ResumeHash     string `json:"resume_hash"`
	SourceEvidence string `json:"source_evidence"`
}

func (b cancellationStopBinding) matches(run platformruntime.Run) bool {
	if b.Version != "execution-cancellation-stop/v1" || b.ScopeDigest != compensation.ScopeDigest(run.Scope) || b.Revision != run.Revision ||
		b.LeaseHash != stopHash([]byte(run.LeaseToken)) || b.RequestHash != stopHash(run.RequestJSON) || b.ResumeHash != stopHash(run.ResumeInputJSON) || len(b.SourceEvidence) != 64 {
		return false
	}
	switch b.Source {
	case "platform-undispatched-claim/v1", "platform-never-claimed/v1", "runtime-process-stop/v1", "platform-waiting-handoff/v1", "platform-group-handoff/v1", "agent-stop-acknowledgement/v1", "platform-internal-task-stop/v1":
		return true
	}
	return false
}

func (s *SQLStore) cancellationStopProofTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) (compensation.StopProof, bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='cancellation_stop_verified' ORDER BY seq DESC LIMIT 1`), run.ID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return compensation.StopProof{}, false, nil
	}
	if err != nil {
		return compensation.StopProof{}, false, err
	}
	var b cancellationStopBinding
	if len(raw) > 2048 || strictStopJSON(raw, &b) != nil || !b.matches(run) {
		return compensation.StopProof{}, false, compensation.ErrConflict
	}
	return compensation.StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: b.ScopeDigest, Revision: b.Revision, EvidenceDigest: stopHash(raw)}, true, nil
}

func (a cancellationAuthority) ConfirmStoppedTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, proof compensation.StopProof) error {
	run, err := a.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if completedEvaluationStatus(run.Status) {
		actual, err := a.runs.completedEvaluationStopProofTx(ctx, tx, run)
		if err != nil {
			return err
		}
		if proof != actual || a.runs.terminalOutcomeFence == nil || a.ports.ValidateCoverageTx == nil {
			return compensation.ErrConflict
		}
		if err = a.runs.terminalOutcomeFence(ctx, tx, scope); err != nil {
			return err
		}
		return a.ports.ValidateCoverageTx(ctx, tx, scope)
	}
	if run.Status != platformruntime.StatusCancelling || run.Revision != proof.Revision || a.runs.terminalOutcomeFence == nil || a.ports.ValidateCoverageTx == nil {
		return compensation.ErrPending
	}
	recorded, found, err := a.runs.cancellationStopProofTx(ctx, tx, run)
	if err != nil {
		return err
	}
	if !found || recorded != proof {
		return compensation.ErrConflict
	}
	if err := a.runs.checkCancellationFenceTx(ctx, tx, scope); err != nil {
		return err
	}
	return a.ports.ValidateCoverageTx(ctx, tx, scope)
}

func (a cancellationAuthority) GuardCompensationTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	run, err := a.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if completedEvaluationStatus(run.Status) {
		proof, err := a.runs.completedEvaluationStopProofTx(ctx, tx, run)
		if err != nil {
			return err
		}
		return a.ConfirmStoppedTx(ctx, tx, scope, proof)
	}
	proof, found, err := a.runs.cancellationStopProofTx(ctx, tx, run)
	if err != nil {
		return err
	}
	if !found {
		return compensation.ErrPending
	}
	return a.ConfirmStoppedTx(ctx, tx, scope, proof)
}

func (a cancellationAuthority) FinishCancellationTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, proof compensation.StopProof) error {
	if err := a.ConfirmStoppedTx(ctx, tx, scope, proof); err != nil {
		return err
	}
	run, err := a.rootTx(ctx, tx, scope)
	if err != nil {
		return err
	}
	if completedEvaluationStatus(run.Status) {
		metadata, _ := json.Marshal(map[string]any{"version": "completed-evaluation-compensation/v1", "parent_run_id": scope.ParentRunID, "scope_digest": proof.ScopeDigest, "stop_evidence_digest": proof.EvidenceDigest, "original_revision": run.Revision})
		_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,clock_timestamp())`), run.ID, "completed_effects_compensated", metadata)
		return err
	}
	_, err = a.runs.finishCancelledTx(ctx, tx, run, map[string]any{
		"source": "platform_cancel", "compensation_version": compensation.ContractVersion,
		"scope_digest": proof.ScopeDigest, "stop_evidence_digest": proof.EvidenceDigest,
	})
	return err
}

type verifiedAgentStopKey struct{}

// This method is reached only after the authenticated gateway confirmed the
// precise generation. HTTP callers cannot supply the private context marker.
func (s *SQLStore) CancelWithAgentAcknowledgement(ctx context.Context, expected platformruntime.Run, executionRevision uint64) (platformruntime.Run, error) {
	if ctx == nil || expected.Status != platformruntime.StatusCancelling || executionRevision == 0 {
		return platformruntime.Run{}, platformruntime.ErrInvalidRequest
	}
	ctx = context.WithValue(ctx, verifiedAgentStopKey{}, executionRevision)
	return s.cancelWithGuard(ctx, expected.ID, expected.Revision, nil, nil, nil, func(ctx context.Context, tx *sql.Tx, actual platformruntime.Run) error {
		if actual.Scope != expected.Scope || actual.LeaseToken != expected.LeaseToken || actual.AgentEndpoint != expected.AgentEndpoint || stopHash(actual.RequestJSON) != stopHash(expected.RequestJSON) || stopHash(actual.ResumeInputJSON) != stopHash(expected.ResumeInputJSON) {
			return platformruntime.ErrRevisionConflict
		}
		revision, err := s.cancellationExecutionRevisionTx(ctx, tx, actual)
		if err != nil {
			return err
		}
		if revision != executionRevision {
			return platformruntime.ErrLeaseConflict
		}
		return nil
	})
}

func (s *SQLStore) stageCancellationCompensationTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run, proof *StopEvidence, handoff *contract.HandlerHandoff, group *contract.AgentGroupHandoff, guarded bool) (platformruntime.Run, error) {
	if run.Status != platformruntime.StatusCancelling || s.cancellationSaga == nil || s.terminalOutcomeFence == nil || s.cancellationPorts.ValidateCoverageTx == nil {
		return platformruntime.Run{}, compensation.ErrUnavailable
	}
	// This same Run lock fences admission. It must include every descendant's
	// stop and settled ledger; a bare Agent acknowledgement is insufficient.
	if err := s.checkCancellationFenceTx(ctx, tx, run.Scope); err != nil {
		return platformruntime.Run{}, stopPhaseError{"compensation_tree_fence", err}
	}
	if _, err := s.cancellationSaga.BeginTx(ctx, tx, run.Scope, run.Revision); err != nil {
		return platformruntime.Run{}, stopPhaseError{"compensation_begin", err}
	}
	if s.cancellationPorts.PrepareCoverageTx != nil {
		if err := s.cancellationPorts.PrepareCoverageTx(ctx, tx, run.Scope, s.cancellationSaga); err != nil {
			return platformruntime.Run{}, stopPhaseError{"compensation_enrollment", err}
		}
	}
	if err := s.cancellationPorts.ValidateCoverageTx(ctx, tx, run.Scope); err != nil {
		return platformruntime.Run{}, stopPhaseError{"compensation_coverage", err}
	}
	stopped, found, err := s.cancellationStopProofTx(ctx, tx, run)
	if err != nil {
		return platformruntime.Run{}, err
	}
	if !found {
		b := cancellationStopBinding{Version: "execution-cancellation-stop/v1", ScopeDigest: compensation.ScopeDigest(run.Scope), Revision: run.Revision,
			LeaseHash: stopHash([]byte(run.LeaseToken)), RequestHash: stopHash(run.RequestJSON), ResumeHash: stopHash(run.ResumeInputJSON)}
		switch {
		case proof != nil:
			if proof.Source != "runtime-process-stop/v1" || len(proof.Digest) != 64 {
				return platformruntime.Run{}, ErrStopEvidenceInvalid
			}
			b.Source, b.SourceEvidence = proof.Source, proof.Digest
		case handoff != nil:
			raw, _ := json.Marshal(handoff)
			b.Source, b.SourceEvidence = "platform-waiting-handoff/v1", stopHash(raw)
		case group != nil:
			raw, _ := json.Marshal(group)
			b.Source, b.SourceEvidence = "platform-group-handoff/v1", stopHash(raw)
		case ctx.Value(verifiedAgentStopKey{}) != nil:
			raw, _ := json.Marshal(map[string]any{"execution_revision": ctx.Value(verifiedAgentStopKey{}), "request_hash": b.RequestHash, "lease_hash": b.LeaseHash})
			b.Source, b.SourceEvidence = "agent-stop-acknowledgement/v1", stopHash(raw)
		case internalIndexOwner(run, run.Scope) && run.LeaseToken != "" && run.Revision >= 2:
			// Only the synchronous internal owner can persist this receipt after
			// execution and model cleanup have returned. Match its exact lease
			// and generation under the cancellation transaction's Run lock.
			want, _ := json.Marshal(internalStopReceipt{ExecutionRevision: run.Revision - 1, LeaseDigest: stopHash([]byte(run.LeaseToken))})
			var raw []byte
			err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='internal_task_stopped' AND payload::jsonb=?::jsonb ORDER BY seq DESC LIMIT 1`), run.ID, want).Scan(&raw)
			if errors.Is(err, sql.ErrNoRows) {
				return platformruntime.Run{}, ErrStopEvidenceAbsent
			}
			if err != nil {
				return platformruntime.Run{}, err
			}
			b.Source, b.SourceEvidence = "platform-internal-task-stop/v1", stopHash(raw)
		case guarded:
			var raw []byte
			if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload FROM platform_execution_event WHERE run_id=? AND event_type='undispatched_cancel_confirmed' ORDER BY seq DESC LIMIT 1`), run.ID).Scan(&raw); err != nil {
				return platformruntime.Run{}, err
			}
			b.Source, b.SourceEvidence = "platform-undispatched-claim/v1", stopHash(raw)
		case run.LeaseToken == "" && run.Revision == 2:
			var untouched bool
			if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT NOT EXISTS(SELECT 1 FROM platform_execution_generation_claim_journal WHERE run_id=?) AND NOT EXISTS(SELECT 1 FROM platform_execution_generation_dispatch_journal WHERE run_id=?) AND NOT EXISTS(SELECT 1 FROM platform_execution_outcome WHERE run_id=?)`), run.ID, run.ID, run.ID).Scan(&untouched); err != nil {
				return platformruntime.Run{}, err
			}
			if !untouched {
				return platformruntime.Run{}, ErrStopEvidenceAbsent
			}
			b.Source, b.SourceEvidence = "platform-never-claimed/v1", stopHash([]byte(b.ScopeDigest+":2:never-claimed"))
		default:
			return platformruntime.Run{}, ErrStopEvidenceAbsent
		}
		if !b.matches(run) {
			return platformruntime.Run{}, ErrStopEvidenceInvalid
		}
		raw, _ := json.Marshal(b)
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_event(run_id,event_type,payload,occurred_at) VALUES(?,?,?,?)`), run.ID, "cancellation_stop_verified", raw, time.Now().UTC()); err != nil {
			return platformruntime.Run{}, err
		}
		stopped = compensation.StopProof{Version: "cancellation-tree-stop/v1", ScopeDigest: b.ScopeDigest, Revision: b.Revision, EvidenceDigest: stopHash(raw)}
	}
	if err = s.cancellationSaga.ConfirmStoppedTx(ctx, tx, run.Scope, stopped); err != nil {
		return platformruntime.Run{}, stopPhaseError{"compensation_stop_commit", err}
	}
	if err = s.cancellationSaga.FinalizeTx(ctx, tx, run.Scope); err != nil {
		if errors.Is(err, compensation.ErrPending) {
			// Commit the stop proof and compensation intent, retaining the Run
			// lease/FIFO and status=cancelling until every receipt is verified.
			return run, nil
		}
		return platformruntime.Run{}, stopPhaseError{"compensation_finalize", err}
	}
	return readExecutionRun(ctx, tx, run.ID, "")
}

// ReconcileCancellationCompensation avoids repeated remote stop requests after
// a durable exact-generation proof. It never executes a forward business call.
func (s *SQLStore) ReconcileCancellationCompensation(ctx context.Context, expected platformruntime.Run) (bool, error) {
	if s.cancellationSaga == nil {
		return false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	run, err := readExecutionRun(ctx, tx, expected.ID, " FOR UPDATE")
	if err != nil {
		return false, err
	}
	if run.Scope != expected.Scope || run.Status != platformruntime.StatusCancelling || run.Revision != expected.Revision || run.LeaseToken != expected.LeaseToken {
		return false, platformruntime.ErrRevisionConflict
	}
	_, found, err := s.cancellationStopProofTx(ctx, tx, run)
	if err != nil || !found {
		return false, err
	}
	if err := s.cancellationSaga.FinalizeTx(ctx, tx, run.Scope); err != nil && !errors.Is(err, compensation.ErrPending) {
		return true, err
	}
	return true, tx.Commit()
}

var _ compensation.Authority = cancellationAuthority{}
