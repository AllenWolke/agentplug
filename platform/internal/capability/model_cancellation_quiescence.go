package capability

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// CheckTaskCancellationModelQuiescence is a cancellation-only composition
// port. The dispatcher must first persist proof that the exact execution
// generation exited. A retained supplier charge is not a running Agent, and
// remains reserved after cancellation. This port grants no retry or refund.
func (m *Module) CheckTaskCancellationModelQuiescence(ctx context.Context, scope sharedkernel.Scope) error {
	store, ok := m.cancellationModelStore(scope)
	if !ok || ctx == nil {
		return ErrModelInvocationReconciliationNeeded
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := m.CheckTaskCancellationModelQuiescenceTx(ctx, tx, scope); err != nil {
		// Do not retain this read connection while the recovery port acquires
		// another connection. The invocation/hold proof has already failed.
		_ = tx.Rollback()
		m.expediteModelReconciliation(ctx, scope)
		return err
	}
	return tx.Commit()
}

// Final cancellation coverage already owns a transaction and execution fences.
// Read the model and money proofs in it rather than acquiring another connection
// while that transaction holds Run/Session locks.
func (m *Module) CheckTaskCancellationModelQuiescenceTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	store, ok := m.cancellationModelStore(scope)
	if !ok || ctx == nil || tx == nil {
		return ErrModelInvocationReconciliationNeeded
	}
	hashes := []string{modelEvidenceScopeHash(scope), modelSelectionScopeHash(scope)}
	for i, hash := range hashes {
		if i > 0 && hash == hashes[0] {
			continue
		}
		if err := store.checkModelQuiescenceTx(ctx, tx, hash, &scope); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) cancellationModelStore(scope sharedkernel.Scope) (*SQLModelInvocationStore, bool) {
	if m == nil || scope.ValidateTrusted() != nil {
		return nil, false
	}
	store, ok := m.modelStore.(*SQLModelInvocationStore)
	return store, ok && store != nil && store.db != nil
}

// This is only the invocation half of the proof. The common checker additionally
// asks the money owner to confirm the exact reservation is still reconcile,
// including Scope, Run, request, fingerprint, approved price and full amount.
// Merely having an unknown row, an expired timer or an Agent ACK is insufficient.
func cancellationRetainsUnknown(owner sharedkernel.Scope, fingerprint, token string, r *BillingRecovery) bool {
	if owner.ValidateTrusted() != nil || r == nil || !r.HoldConfirmed || r.Event != nil || r.Decision != nil || r.Unsent ||
		!r.SendDeadline.IsZero() || !r.AdmissionUntil.IsZero() || !recoverableProviderFailure(r.FailureKind) ||
		token == "" || token != r.AttemptToken || r.PriceID == "" || r.PriceID != r.Reservation.PriceVersionID ||
		!isRouteSHA(fingerprint) || r.Reservation.Fingerprint != fingerprint {
		return false
	}
	b := r.Reservation
	return b.RunID == owner.RunID && b.ReservationID != "" && b.RequestID != "" && b.ReserveMicros >= 0 &&
		b.Scope.TenantID == owner.TenantID && b.Scope.DepartmentID == owner.DepartmentID &&
		b.Scope.ApplicationID == owner.ApplicationID && b.Scope.AgentID == owner.AgentID &&
		b.Scope.AgentVersionID == owner.AgentVersionID
}
