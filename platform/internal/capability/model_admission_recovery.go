package capability

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type modelBudgetPreparationKey struct{}
type modelBudgetPreparation struct{ scope, key, fingerprint, token string }

// Only the gateway can bind a preparation nonce. Request JSON cannot supply it.
func withModelBudgetPreparation(ctx context.Context, scope, key, fingerprint, token string) context.Context {
	return context.WithValue(ctx, modelBudgetPreparationKey{}, modelBudgetPreparation{scope, key, fingerprint, token})
}

// RecordBudgetAdmissionTx closes the commit/acknowledgement gap. Budget, tree
// binding and this explicit pre-send proof either all commit or all roll back.
// Sending must first replace this proof with the existing durable send intent.
func (s *SQLModelInvocationStore) RecordBudgetAdmissionTx(ctx context.Context, tx *sql.Tx, reservation usagecost.ModelBudgetReservation) error {
	p, ok := ctx.Value(modelBudgetPreparationKey{}).(modelBudgetPreparation)
	if s == nil || tx == nil || !ok || p.scope == "" || p.key == "" || p.token == "" || p.fingerprint != reservation.Fingerprint || reservation.ReservationID == "" || reservation.Status != "pending" {
		return ErrModelInvocationConflict
	}
	var state, status, fingerprint, token string
	var deadline sql.NullTime
	var raw, response sql.NullString
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,billing_state,fingerprint,invocation_token,preparation_deadline,billing_recovery_json,response_json FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=? FOR UPDATE`), p.scope, p.key).Scan(&status, &state, &fingerprint, &token, &deadline, &raw, &response)
	if err != nil {
		return err
	}
	if response.Valid || fingerprint != p.fingerprint || token != p.token || !deadline.Valid || !deadline.Time.After(time.Now()) {
		return ErrModelInvocationConflict
	}
	if status == "reconcile" && state == "admitted" {
		var saved BillingRecovery
		if !raw.Valid || json.Unmarshal([]byte(raw.String), &saved) != nil || !saved.AdmissionUntil.Equal(deadline.Time) || saved.AttemptToken != token || saved.Event != nil || saved.Decision != nil || !saved.SendDeadline.IsZero() || saved.PriceID != reservation.PriceVersionID || !budgetRecoveryMatches(saved.Reservation, reservation) {
			return ErrModelInvocationConflict
		}
		return nil // Exact admission replay, never an independent execution.
	}
	if status != "running" || state != "preparing" || raw.Valid {
		return ErrModelInvocationConflict
	}
	intent, err := json.Marshal(BillingRecovery{Reservation: reservation, PriceID: reservation.PriceVersionID, AttemptToken: token, AdmissionUntil: deadline.Time})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',billing_state='admitted',billing_recovery_json=?,billing_retry_at=preparation_deadline,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=?`), string(intent), p.scope, p.key)
	return err
}
