package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// ModelBudgetEvidence discloses billing metadata only. It contains no model
// response, prompt, credential or execution attempt token.
type ModelBudgetEvidence struct {
	Event       *usagecost.Event
	PriceID     string
	NoChargeRef string
	Fingerprint string
}

func budgetRecoveryMatches(a, b usagecost.ModelBudgetReservation) bool {
	return a.ReservationID == b.ReservationID && a.Scope == b.Scope && a.RunID == b.RunID && a.Window.Start.Equal(b.Window.Start) && a.Window.End.Equal(b.Window.End) && a.RequestID == b.RequestID && a.Fingerprint == b.Fingerprint && a.PriceVersionID == b.PriceVersionID && a.BudgetLimitMicros == b.BudgetLimitMicros && a.ReserveMicros == b.ReserveMicros && a.ExpiresAt.Equal(b.ExpiresAt)
}

// BudgetEvidenceTx reads this module's original recovery envelope under the
// caller's transaction. It never invokes a provider, modifies a receipt or
// grants model-result access. Accounting composition must bind the original
// actor independently through UsageCost's saved model binding.
func (s *SQLModelInvocationStore) BudgetEvidenceTx(ctx context.Context, tx *sql.Tx, reservation usagecost.ModelBudgetReservation) (ModelBudgetEvidence, error) {
	if s == nil || tx == nil || reservation.ReservationID == "" || len(reservation.ReservationID) > 128 {
		return ModelBudgetEvidence{}, ErrModelInvocationConflict
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT scope_hash,idempotency_key,fingerprint,billing_recovery_json FROM platform_model_invocation WHERE billing_recovery_json IS NOT NULL AND (billing_recovery_json::jsonb->'reservation'->>'reservation_id')=? LIMIT 2 FOR SHARE`), reservation.ReservationID)
	if err != nil {
		return ModelBudgetEvidence{}, err
	}
	defer rows.Close()
	var scope, key, fingerprint, raw string
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return ModelBudgetEvidence{}, err
		}
		return ModelBudgetEvidence{}, ErrModelInvocationConflict
	}
	if err = rows.Scan(&scope, &key, &fingerprint, &raw); err != nil {
		return ModelBudgetEvidence{}, err
	}
	if rows.Next() {
		return ModelBudgetEvidence{}, ErrModelInvocationConflict
	}
	if err = rows.Err(); err != nil {
		return ModelBudgetEvidence{}, err
	}
	if err = rows.Close(); err != nil {
		return ModelBudgetEvidence{}, err
	}
	if len(raw) > 65536 || fingerprint != reservation.Fingerprint {
		return ModelBudgetEvidence{}, ErrModelInvocationConflict
	}
	var recovery BillingRecovery
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&recovery) != nil || decoder.Decode(new(any)) != io.EOF || !budgetRecoveryMatches(recovery.Reservation, reservation) || recovery.PriceID != reservation.PriceVersionID {
		return ModelBudgetEvidence{}, ErrModelInvocationConflict
	}
	result := ModelBudgetEvidence{PriceID: recovery.PriceID, Event: recovery.Event}
	if recovery.Event != nil {
		e := *recovery.Event
		if e.Validate() != nil || e.Scope.TenantID != reservation.Scope.TenantID || e.Scope.DepartmentID != reservation.Scope.DepartmentID || e.Scope.ApplicationID != reservation.Scope.ApplicationID || e.Scope.AgentID != reservation.Scope.AgentID || e.Scope.AgentVersionID != reservation.Scope.AgentVersionID || e.Scope.RunID != reservation.RunID {
			return ModelBudgetEvidence{}, ErrModelInvocationConflict
		}
		result.Event = &e
	}
	if decision := recovery.Decision; decision != nil {
		if !validBillingDecision(*decision) || decision.ReservationID != reservation.ReservationID || decision.ActorTenant != reservation.Scope.TenantID {
			return ModelBudgetEvidence{}, ErrModelInvocationConflict
		}
		var storedID, status string
		err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT decision_id,status FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=? AND reservation_id=? AND decision_id=? FOR SHARE`), scope, key, reservation.ReservationID, decision.ID).Scan(&storedID, &status)
		if err != nil || storedID != decision.ID || (status != "accepted" && status != "applied") {
			return ModelBudgetEvidence{}, ErrModelInvocationConflict
		}
		if decision.Outcome == "no_charge" {
			if result.Event != nil {
				return ModelBudgetEvidence{}, ErrModelInvocationConflict
			}
			result.NoChargeRef = decision.ProviderRef
		}
	}
	encoded, err := json.Marshal([]any{reservation.ReservationID, result.PriceID, result.Event, result.NoChargeRef})
	if err != nil {
		return ModelBudgetEvidence{}, err
	}
	hash := sha256.Sum256(encoded)
	result.Fingerprint = hex.EncodeToString(hash[:])
	return result, nil
}
