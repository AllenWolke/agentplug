package usagecost

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sqlutil"
)

// A retained hold is not a settlement or release. Callers use this read-only
// port to finish business execution while leaving the full exposure reserved.
type ModelBudgetRetentionReader interface {
	BudgetRetentionsConfirmedTx(context.Context, *sql.Tx, []ModelBudgetReservation) (bool, error)
}

func (s *SQLStore) BudgetRetentionsConfirmedTx(ctx context.Context, tx *sql.Tx, reservations []ModelBudgetReservation) (bool, error) {
	if s == nil || tx == nil || ctx == nil {
		return false, ErrInvalidUsage
	}
	for _, r := range reservations {
		if r.ReservationID == "" || r.RunID == "" || r.RequestID == "" || r.Fingerprint == "" || r.PriceVersionID == "" || r.ReserveMicros < 0 {
			return false, ErrInvalidUsage
		}
		if _, _, err := canonicalBudgetScope(r.Scope); err != nil {
			return false, err
		}
	}
	if len(reservations) == 0 {
		return true, nil
	}
	raw, err := json.Marshal(reservations)
	if err != nil {
		return false, err
	}
	var confirmed bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT NOT EXISTS (
 SELECT 1 FROM jsonb_array_elements(?::jsonb) AS proof
 WHERE NOT EXISTS (
 SELECT 1 FROM platform_model_budget_reservation b
 WHERE b.reservation_id=proof->>'reservation_id' AND b.status='reconcile'
 AND b.tenant_id=proof->'scope'->>'tenant_id' AND b.department_id=proof->'scope'->>'department_id'
 AND b.application_id=proof->'scope'->>'application_id' AND b.agent_id=proof->'scope'->>'agent_id'
 AND b.agent_version_id=proof->'scope'->>'agent_version_id' AND b.run_id=proof->>'run_id'
 AND b.request_id=proof->>'request_id' AND b.request_fingerprint=proof->>'fingerprint'
 AND b.price_version_id=proof->>'price_version_id' AND b.reserve_micros=(proof->>'reserve_micros')::bigint
 ))`), string(raw)).Scan(&confirmed)
	return confirmed, err
}

var _ ModelBudgetRetentionReader = (*SQLStore)(nil)
