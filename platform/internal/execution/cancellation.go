package execution

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/agentgateway"
	"github.com/lexagent/platform/internal/compensation"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
)

// Cancellation reconciliation budgets. The scan lists one bounded page; each
// due row confirms its stop under its own detached budget so the 10s remote
// transport ceiling is never truncated by the scan deadline; the round stays
// bounded so dispatch and outcome reconciliation keep their ticker share.
const (
	cancellationScanBound  = 5 * time.Second
	cancellationItemBound  = 15 * time.Second
	cancellationRoundBound = 60 * time.Second
)

type cancellationRepository interface {
	BeginCancellation(string, uint64) (platformruntime.Run, error)
	PendingCancellations(int) ([]platformruntime.Run, error)
}

// Stop phases are fixed platform labels; remote error messages and credentials
// must never enter cancellation logs.
type stopPhaseError struct {
	phase string
	cause error
}

func (e stopPhaseError) Error() string { return "execution stop confirmation failed" }
func (e stopPhaseError) Unwrap() error { return e.cause }
func stopDiagnostic(err error) (string, string) {
	phase, code := "unclassified", "REMOTE_STOP_UNCONFIRMED"
	var step stopPhaseError
	if errors.As(err, &step) {
		phase = step.phase
		// The innermost fixed label identifies the failed transaction stage.
		for cause := errors.Unwrap(step); cause != nil; cause = errors.Unwrap(cause) {
			if inner, ok := cause.(stopPhaseError); ok {
				phase = inner.phase
			}
		}
	}
	for _, known := range []struct {
		cause error
		code  string
	}{
		{compensation.ErrPending, "COMPENSATION_PENDING"},
		{compensation.ErrConflict, "COMPENSATION_CONFLICT"},
		{compensation.ErrUnavailable, "COMPENSATION_UNAVAILABLE"},
		{compensation.ErrInvalid, "COMPENSATION_INVALID"},
		{ErrStopEvidenceInvalid, "STOP_EVIDENCE_INVALID"},
		{platformruntime.ErrLeaseConflict, "LEASE_CONFLICT"},
		{platformruntime.ErrRevisionConflict, "REVISION_CONFLICT"},
	} {
		if errors.Is(err, known.cause) {
			code = known.code
			break
		}
	}
	var database interface{ SQLState() string }
	if errors.As(err, &database) {
		switch database.SQLState() {
		case "40P01", "55P03", "57014", "42501", "25006", "42P01", "42703":
			code = "DATABASE_" + database.SQLState()
		}
	}
	var remote contract.AppError
	if errors.As(err, &remote) {
		switch remote.Code {
		case "CAPABILITY_INVALID", "REMOTE_STOP_UNCONFIRMED", "RUN_UNKNOWN", "REQUEST_INVALID":
			code = remote.Code
		}
	}
	if phase == "model_settlement" && code == "REMOTE_STOP_UNCONFIRMED" {
		code = "MODEL_SETTLEMENT_PENDING"
	}
	return phase, code
}

// stopUncertainExecution never assumes a failed transport stopped a remote graph.
// 网络错误不等于远程图退出；保持 FIFO 占用直到签名停止确认。
func (d *Dispatcher) stopUncertainExecution(running platformruntime.Run, code string) error {
	// Persist which stop path/code actually fired so an unconfirmed tail is
	// auditable by code instead of inferred from downstream cancellation logs.
	log.Printf("execution stop uncertain run_id=%q revision=%d code=%s", running.ID, running.Revision, code)
	store, ok := d.repository.(interface {
		BeginCancellationWithReason(string, uint64, string) (platformruntime.Run, error)
	})
	if !ok {
		return errors.New("stop intent repository unavailable")
	}
	pending, err := store.BeginCancellationWithReason(running.ID, running.Revision, code)
	if err != nil {
		current, getErr := d.repository.Get(running.ID)
		if getErr == nil && (current.Status == platformruntime.StatusCancelled || current.Status == platformruntime.StatusSucceeded || current.Status == platformruntime.StatusFailed || current.Status == platformruntime.StatusWaiting) {
			return nil
		}
		return err
	}
	if pending.Status == platformruntime.StatusCancelled {
		return nil
	}
	// The Invoke context can already be cancelled; stopping needs a new bounded
	// control context, not a cancelled transport or a fresh business grant.
	// Invoke context 可能已取消；停止控制使用新的有界 context，不恢复业务授权。
	// The control budget must cover a loaded database plus the remote stop; 2s was
	// shorter than the observed admission/commit latency and could never confirm a
	// stop under load, leaving the Run pending forever. Reuse the per-item bound.
	ctx, cancel := context.WithTimeout(context.Background(), cancellationItemBound)
	defer cancel()
	if err := d.confirmCancellation(ctx, pending); err != nil {
		telemetry.RecordExecutionReconciliationFailure("cancellation")
		phase, reason := stopDiagnostic(err)
		log.Printf("execution stop pending run_id=%q phase=%s code=%s", running.ID, phase, reason)
	}
	return nil
}

// requestCancellation persists intent before sending the control command.
// 先保存意图，再投递控制命令；网络错误不能冒充远程停止确认。
func (m *Module) requestCancellation(ctx context.Context, run platformruntime.Run, expected uint64) (platformruntime.Run, error) {
	store, ok := m.store.(cancellationRepository)
	if !ok {
		return platformruntime.Run{}, errors.New("cancellation repository unavailable")
	}
	pending, err := store.BeginCancellation(run.ID, expected)
	if err != nil || pending.Status == platformruntime.StatusCancelled {
		return pending, err
	}
	if pending.LeaseToken == "" {
		// Accepted/waiting has no dispatched generation owning a graph.
		// 未领取或已返回 waiting 的任务没有正在执行图的世代。
		return m.store.Cancel(pending.ID, pending.Revision)
	}
	if m.dispatcher == nil {
		return pending, nil
	}
	if err := m.dispatcher.confirmCancellation(ctx, pending); err != nil {
		telemetry.RecordExecutionReconciliationFailure("cancellation")
		phase, code := stopDiagnostic(err)
		log.Printf("execution cancellation pending run_id=%q phase=%s code=%s", pending.ID, phase, code)
		// Durable intent is the response, not a fabricated terminal success.
		// 返回持久化待取消状态，不伪造终态；补偿循环继续处理。
		return pending, nil
	}
	return m.store.Get(pending.ID)
}

func (d *Dispatcher) confirmCancellation(ctx context.Context, pending platformruntime.Run) error {
	if d.recoveryHolds.Contains(pending.ID) {
		return stopPhaseError{"operator_recovery_hold", sharedkernel.ErrAutomaticRecoveryHeld}
	}
	if pending.Status != platformruntime.StatusCancelling && pending.Status != platformruntime.StatusRecovering {
		return platformruntime.ErrInvalidTransition
	}
	if pending.Status == platformruntime.StatusCancelling {
		if store, ok := d.repository.(interface {
			ReconcileCancellationCompensation(context.Context, platformruntime.Run) (bool, error)
		}); ok {
			stopped, err := store.ReconcileCancellationCompensation(ctx, pending)
			if err != nil {
				return stopPhaseError{"compensation_reconciliation", err}
			}
			if stopped {
				d.Cancel(pending.ID)
				return nil
			}
		}
	}
	var acknowledgedRevision uint64
	ackStore, supportsAck := d.repository.(cancellationAcknowledgementStore)
	if supportsAck && pending.Status == platformruntime.StatusCancelling && pending.LeaseToken != "" {
		revision, found, err := ackStore.ReadCancellationAgentAcknowledgement(ctx, pending)
		if err != nil {
			return stopPhaseError{"agent_stop_receipt_read", err}
		}
		if found {
			acknowledgedRevision = revision
		}
	}
	if pending.Status == platformruntime.StatusCancelling && pending.LeaseToken != "" && acknowledgedRevision == 0 {
		if store, ok := d.repository.(interface {
			TryCancelUndispatched(context.Context, platformruntime.Run) (bool, error)
		}); ok {
			cancelled, err := store.TryCancelUndispatched(ctx, pending)
			if err != nil {
				return stopPhaseError{"undispatched_cancel", err}
			}
			if cancelled {
				d.Cancel(pending.ID)
				return nil
			}
		}
	}
	if pending.Status == platformruntime.StatusRecovering {
		if store, ok := d.repository.(interface {
			TryRecoverUndispatched(context.Context, string, uint64) (bool, error)
		}); ok {
			requeued, err := store.TryRecoverUndispatched(ctx, pending.ID, pending.Revision)
			if err != nil {
				return stopPhaseError{"undispatched_recovery", err}
			}
			if requeued {
				d.Cancel(pending.ID)
				return nil
			}
		}
	}
	if pending.LeaseToken == "" {
		_, err := d.repository.Cancel(pending.ID, pending.Revision)
		return err
	}
	var request contract.ExecuteRequest
	if err := contract.DecodeJSONPreservingNumbers(pending.RequestJSON, &request); err != nil || request.Scope.RunID != pending.ID {
		return platformruntime.ErrInvalidRequest
	}
	if err := bindRunAuthorization(pending, &request); err != nil {
		return platformruntime.ErrInvalidRequest
	}
	scope := pending.Scope
	expected := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, InstallationID: scope.InstallationID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID, DelegationDepth: request.Scope.DelegationDepth}
	if request.Scope != expected {
		return platformruntime.ErrInvalidRequest
	}
	var evidence StopEvidence
	var handoff *contract.HandlerHandoff
	var groupHandoff *contract.AgentGroupHandoff
	groupStore, supportsGroup := d.repository.(interface {
		CancellationAgentGroupHandoff(context.Context, platformruntime.Run) (contract.AgentGroupHandoff, error)
		CancelWithAgentGroupHandoff(string, uint64, contract.AgentGroupHandoff) (platformruntime.Run, error)
	})
	handoffStore, supportsHandoff := d.repository.(interface {
		CancellationWaitingHandoff(context.Context, platformruntime.Run) (contract.HandlerHandoff, error)
		CancelWithWaitingHandoff(string, uint64, contract.HandlerHandoff) (platformruntime.Run, error)
	})
	if acknowledgedRevision == 0 && supportsHandoff && pending.Status == platformruntime.StatusCancelling {
		receipt, err := handoffStore.CancellationWaitingHandoff(ctx, pending)
		if err != nil && !errors.Is(err, ErrStopEvidenceAbsent) {
			return stopPhaseError{"waiting_handoff", err}
		}
		if err == nil {
			handoff = &receipt
		}
	}
	if acknowledgedRevision == 0 && handoff == nil && supportsGroup && pending.Status == platformruntime.StatusCancelling {
		receipt, err := groupStore.CancellationAgentGroupHandoff(ctx, pending)
		if err != nil && !errors.Is(err, ErrStopEvidenceAbsent) {
			return stopPhaseError{"group_wait_handoff", err}
		}
		if err == nil {
			groupHandoff = &receipt
		}
	}
	if acknowledgedRevision == 0 && handoff == nil && groupHandoff == nil && d.stopEvidence != nil {
		proof, err := d.stopEvidence.VerifyStopped(ctx, pending)
		if err != nil && !errors.Is(err, ErrStopEvidenceAbsent) {
			return stopPhaseError{"controller_stop_evidence", err}
		}
		if err == nil {
			evidence = proof
		}
	}
	if acknowledgedRevision == 0 && handoff == nil && groupHandoff == nil && evidence.Source == "" {
		executionRevision, err := d.cancellationExecutionRevision(ctx, pending)
		if err != nil {
			return stopPhaseError{"dispatch_generation", err}
		}
		transport, ok := d.gateway.(interface {
			Cancel(context.Context, agentgateway.Target, contract.ExecuteRequest) (contract.ExecuteResponse, error)
		})
		if !ok || d.signer == nil {
			return errors.New("signed cancellation transport unavailable")
		}
		request.Operation = "cancel"
		request.ResumeInput = nil
		request.ContextToken = ""
		target, err := targetFromRun(pending, request)
		if err != nil {
			return stopPhaseError{"cancel_target", err}
		}
		// Waiting outcomes and stop intent both advance the Run head. Only the
		// recorded dispatch identifies the exact generation supervised by the SDK.
		// waiting 结果和取消意图都会递增 Head；执行世代必须取可信投递记录。
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		token, err := d.signer.Sign(sharedkernel.BindExecutionLease(callCtx, executionRevision, pending.LeaseToken), pending.Scope, request)
		if err != nil || token == "" {
			return errors.New("cancellation signing failed")
		}
		request.ContextToken = token
		response, err := transport.Cancel(callCtx, target, request)
		if err != nil {
			return stopPhaseError{"remote_transport", err}
		}
		if response.RunID != pending.ID || response.ProtocolVersion != contract.ProtocolVersion || response.Status != "cancelled" || response.Error != nil {
			return stopPhaseError{"remote_response", agentgateway.ErrInvalidResponse}
		}
		acknowledgedRevision = executionRevision
		if supportsAck && pending.Status == platformruntime.StatusCancelling {
			if err := ackStore.RecordCancellationAgentAcknowledgement(ctx, pending, acknowledgedRevision); err != nil {
				return stopPhaseError{"agent_stop_receipt_commit", err}
			}
		}
	}
	// Remote exit is necessary but insufficient: an interrupted HTTP client may
	// leave a provider charge awaiting reconciliation. Retain FIFO until settled.
	settlement := d.stopQuiescence
	if pending.Status == platformruntime.StatusCancelling && d.cancellationQuiescence != nil {
		settlement = d.cancellationQuiescence
	}
	if settlement != nil {
		if err := settlement(ctx, pending.Scope); err != nil {
			return stopPhaseError{"model_settlement", err}
		}
	}
	if handoff != nil {
		// The receipt proves only this paused handler exited. Keep provider
		// settlement above, and repeat all persisted bindings in the final CAS.
		if _, err := handoffStore.CancelWithWaitingHandoff(pending.ID, pending.Revision, *handoff); err != nil {
			return stopPhaseError{"waiting_handoff_commit", err}
		}
		d.Cancel(pending.ID)
		return nil
	}
	if groupHandoff != nil {
		if _, err := groupStore.CancelWithAgentGroupHandoff(pending.ID, pending.Revision, *groupHandoff); err != nil {
			return stopPhaseError{"group_wait_handoff_commit", err}
		}
		d.Cancel(pending.ID)
		return nil
	}
	if evidence.Source != "" {
		// Production repositories persist the controller proof in the same CAS
		// transaction as the stop outcome. Never treat a verifier error as exit.
		store, ok := d.repository.(interface {
			CompleteRecoveryWithStopEvidence(string, uint64, StopEvidence) (platformruntime.Run, error)
			CancelWithStopEvidence(string, uint64, StopEvidence) (platformruntime.Run, error)
		})
		if !ok {
			return errors.New("atomic stop evidence repository unavailable")
		}
		var err error
		if pending.Status == platformruntime.StatusRecovering {
			_, err = store.CompleteRecoveryWithStopEvidence(pending.ID, pending.Revision, evidence)
		} else {
			_, err = store.CancelWithStopEvidence(pending.ID, pending.Revision, evidence)
		}
		if err != nil {
			return stopPhaseError{"controller_stop_commit", err}
		}
		d.Cancel(pending.ID)
		return nil
	}
	if pending.Status == platformruntime.StatusRecovering {
		store, ok := d.repository.(interface {
			CompleteRecovery(string, uint64) (platformruntime.Run, error)
		})
		if !ok {
			return errors.New("recovery repository unavailable")
		}
		if _, err := store.CompleteRecovery(pending.ID, pending.Revision); err != nil {
			return stopPhaseError{"recovery_stop_commit", err}
		}
	} else {
		if store, ok := d.repository.(interface {
			CancelWithAgentAcknowledgement(context.Context, platformruntime.Run, uint64) (platformruntime.Run, error)
		}); ok && acknowledgedRevision != 0 {
			if _, err := store.CancelWithAgentAcknowledgement(ctx, pending, acknowledgedRevision); err != nil {
				return stopPhaseError{"agent_stop_commit", err}
			}
		} else {
			if _, err := d.repository.Cancel(pending.ID, pending.Revision); err != nil {
				return err
			}
		}
	}
	d.Cancel(pending.ID)
	return nil
}

// cancellationExecutionRevision grants no business admission and never guesses
// a missing generation. SQL additionally verifies the immutable dispatch journal.
// 只解析停止控制绑定，不恢复业务授权；缺少投递证明时保持待确认状态。
func (d *Dispatcher) cancellationExecutionRevision(ctx context.Context, pending platformruntime.Run) (uint64, error) {
	if resolver, ok := d.repository.(interface {
		CancellationExecutionRevision(context.Context, platformruntime.Run) (uint64, error)
	}); ok {
		return resolver.CancellationExecutionRevision(ctx, pending)
	}
	current, err := d.repository.Get(pending.ID)
	if err != nil {
		return 0, err
	}
	if current.Scope != pending.Scope || current.Status != pending.Status || current.Revision != pending.Revision || current.LeaseToken == "" || current.LeaseToken != pending.LeaseToken {
		return 0, platformruntime.ErrRevisionConflict
	}
	command, err := d.repository.GetDispatchCommand(pending.ID)
	if err != nil {
		return 0, err
	}
	if command.Validate() != nil || command.RunID != pending.ID || command.Revision >= pending.Revision {
		return 0, platformruntime.ErrInvalidRequest
	}
	return command.Revision, nil
}

func (d *Dispatcher) reconcileCancellations(ctx context.Context) {
	store, ok := d.repository.(cancellationRepository)
	if !ok {
		return
	}
	d.cancellationScanMu.Lock()
	defer d.cancellationScanMu.Unlock()
	parent := ctx
	// The scan budget lists one bounded page only. A due row's stop
	// confirmation can legitimately wait for a remote stop acknowledgement
	// (the transport ceiling alone is 10s), so truncating it under the scan
	// deadline misreports an unconfirmed stop as failed and backs the row off.
	// Each visited row therefore gets its own bounded budget detached from the
	// scan deadline, and the whole round stays bounded so the dispatcher ticker
	// still services dispatch and outcome reconciliation.
	scanCtx, scanCancel := context.WithTimeout(parent, cancellationScanBound)
	defer scanCancel()
	const batchSize = 16
	var runs []platformruntime.Run
	var err error
	paged, hasCursor := d.repository.(interface {
		ListPendingCancellationsAfter(context.Context, string, int) ([]platformruntime.Run, error)
	})
	headers, hasHeaders := d.repository.(interface {
		ListPendingCancellationHeadersAfter(context.Context, string, int) ([]platformruntime.Run, error)
		GetContext(context.Context, string) (platformruntime.Run, error)
	})
	if hasHeaders {
		hasCursor = true
		runs, err = headers.ListPendingCancellationHeadersAfter(scanCtx, d.cancellationCursor, batchSize)
	} else if hasCursor {
		runs, err = paged.ListPendingCancellationsAfter(scanCtx, d.cancellationCursor, batchSize)
	} else {
		runs, err = store.PendingCancellations(batchSize)
	}
	if err != nil {
		telemetry.RecordExecutionReconciliationFailure("cancellation")
		log.Printf("execution cancellation reconciliation code=CANCEL_QUERY_FAILED")
		return
	}
	if len(runs) == 0 {
		d.cancellationCursor = ""
		return
	}
	roundCtx, roundCancel := context.WithTimeout(context.WithoutCancel(parent), cancellationRoundBound)
	defer roundCancel()
	for _, run := range runs {
		if roundCtx.Err() != nil || parent.Err() != nil {
			return
		}
		// A backed-off row was visited too: advance past it so another Run can
		// proceed. A deadline still cannot skip an unvisited page tail.
		if hasCursor {
			d.cancellationCursor = run.ID
		}
		if d.recoveryHolds.Contains(run.ID) {
			continue
		}
		if !d.cancellationDue(run, time.Now()) {
			continue
		}
		func() {
			itemCtx, itemCancel := context.WithTimeout(context.WithoutCancel(parent), cancellationItemBound)
			defer itemCancel()
			if hasHeaders {
				// Only a due row pays for the full request; a concurrent terminal
				// transition between the two reads is simply skipped this round.
				full, err := headers.GetContext(itemCtx, run.ID)
				if err != nil {
					telemetry.RecordExecutionReconciliationFailure("cancellation")
					log.Printf("execution cancellation reconciliation code=CANCEL_QUERY_FAILED")
					return
				}
				if full.Status != platformruntime.StatusCancelling && full.Status != platformruntime.StatusRecovering {
					return
				}
				run = full
			}
			if err := d.confirmCancellation(itemCtx, run); err != nil {
				d.deferCancellation(run, time.Now())
				telemetry.RecordExecutionReconciliationFailure("cancellation")
				phase, code := stopDiagnostic(err)
				log.Printf("execution cancellation pending run_id=%q phase=%s code=%s", run.ID, phase, code)
			} else {
				delete(d.cancellationRetries, run.ID)
			}
		}()
	}
}
