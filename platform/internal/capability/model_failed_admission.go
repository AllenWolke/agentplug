package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// RecoverFailedPreparationAdmission is an internal maintenance port, not an
// HTTP refund API. It repairs the old commit/ACK gap only when the persisted
// failed/done preparation transition proves that send was never entered.
// A missing response, timeout, expired hold or zero price alone is NOT proof.
// The normal billing worker applies the audited decision to both ledgers.
func (s *SQLModelInvocationStore) RecoverFailedPreparationAdmission(ctx context.Context, tree usagecost.ModelPreparationBindingReader, window usagecost.ModelPreparationReconciliationWriter, key string, reservation usagecost.ModelBudgetReservation) error {
	if s == nil || tree == nil || window == nil || key == "" || len(key) > 255 {
		return ErrModelInvocationConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	binding, err := tree.ModelBindingTx(ctx, tx, reservation)
	if err != nil {
		return err
	}
	scope := modelEvidenceScopeHash(binding.Scope)
	var state, status, fingerprint, token string
	var response, recovery sql.NullString
	var deadline sql.NullTime
	var created, updated time.Time
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,billing_state,fingerprint,invocation_token,preparation_deadline,response_json,billing_recovery_json,created_at,updated_at FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), scope, key).Scan(&status, &state, &fingerprint, &token, &deadline, &response, &recovery, &created, &updated)
	if err != nil {
		return err
	}
	decisionID := "admission-repair-" + reservation.ReservationID
	if fingerprint != reservation.Fingerprint {
		return ErrModelInvocationConflict
	}
	if recovery.Valid {
		var saved BillingRecovery
		if json.Unmarshal([]byte(recovery.String), &saved) != nil || !budgetRecoveryMatches(saved.Reservation, reservation) || saved.Decision == nil || saved.Decision.ID != decisionID || !saved.Unsent || saved.Event != nil || response.Valid || (state != "decision_pending" && state != "resolved") {
			return ErrModelInvocationConflict
		}
		return tx.Commit() // Exact repair replay; the worker owns settlement.
	}
	// Only FailPreparation/RecoverExpiredPreparations can produce this tuple.
	// Both require preparing + no send intent and clear the old attempt nonce.
	if status != "failed" || state != "done" || token != "" || deadline.Valid || response.Valid {
		return ErrModelInvocationConflict
	}
	var count int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_model_invocation WHERE scope_hash=? AND fingerprint=?`), scope, fingerprint).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrModelInvocationConflict
	}
	// An ambiguous retry may have used the same fingerprint. Require a unique
	// durable reservation and its admission within this preparation's lifetime.
	r := reservation
	unique, err := tree.UniqueFailedPreparationAdmissionTx(ctx, tx, r, created, updated)
	if err != nil {
		return err
	}
	if !unique {
		return ErrModelInvocationConflict
	}
	d := BillingDecision{ID: decisionID, ActorID: "system:model-admission-recovery", ActorTenant: r.Scope.TenantID, ReservationID: r.ReservationID, Outcome: "no_charge", Reason: "durable failed preparation fences send; unique original atomic tree/window admission", ProviderRef: "system:failed-preparation:" + r.ReservationID}
	if !validBillingDecision(d) {
		return ErrModelInvocationConflict
	}
	// Retain the entire window hold while making it eligible for the existing
	// decision worker. Neither ledger's balance is released in this transaction.
	if err = window.MarkReconciliationNeededTx(ctx, tx, r); err != nil {
		return err
	}
	intent := BillingRecovery{Reservation: r, PriceID: r.PriceVersionID, Decision: &d, Unsent: true}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	// This uses the v1 decision protocol; the old worker can finish the repair.
	dj, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_billing_decision(scope_hash,idempotency_key,reservation_id,decision_id,decision_json,status,created_at) VALUES(?,?,?,?,?,'accepted',clock_timestamp())`), scope, key, r.ReservationID, d.ID, string(dj)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',billing_state='decision_pending',billing_recovery_json=?,billing_retry_at=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=?`), string(raw), scope, key); err != nil {
		return err
	}
	return tx.Commit()
}
