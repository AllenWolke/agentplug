package usagecost

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sqlutil"
)

// ModelBudgetClosure 是账务关闭证明的请求，不携带模型输入或输出。
type ModelBudgetClosure struct {
	Reservation ModelBudgetReservation `json:"reservation"`
	Status      string                 `json:"status"`
}

// ModelBudgetClosureReader 在调用者的同一数据库快照内验证预占身份与终态。
// 其他模块通过这个端口核验账务，不直接读取 UsageCost 的表。
type ModelBudgetClosureReader interface {
	BudgetClosuresConfirmedTx(context.Context, *sql.Tx, []ModelBudgetClosure) (bool, error)
}

func (s *SQLStore) BudgetClosuresConfirmedTx(ctx context.Context, tx *sql.Tx, closures []ModelBudgetClosure) (bool, error) {
	if s == nil || tx == nil || ctx == nil {
		return false, ErrInvalidUsage
	}
	for _, closure := range closures {
		r := closure.Reservation
		if (closure.Status != "settled" && closure.Status != "released") || r.ReservationID == "" || r.RunID == "" || r.RequestID == "" || r.Fingerprint == "" || r.PriceVersionID == "" {
			return false, ErrInvalidUsage
		}
		if _, _, err := canonicalBudgetScope(r.Scope); err != nil {
			return false, err
		}
	}
	if len(closures) == 0 {
		return true, nil
	}
	raw, err := json.Marshal(closures)
	if err != nil {
		return false, err
	}
	var confirmed bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT NOT EXISTS (
 SELECT 1 FROM jsonb_to_recordset(?::jsonb) AS proof(reservation jsonb,status text)
 WHERE NOT EXISTS (
  SELECT 1 FROM platform_model_budget_reservation b
  WHERE b.reservation_id=proof.reservation->>'reservation_id' AND b.status=proof.status
   AND b.tenant_id=proof.reservation->'scope'->>'tenant_id'
   AND b.department_id=proof.reservation->'scope'->>'department_id'
   AND b.application_id=proof.reservation->'scope'->>'application_id'
   AND b.agent_id=proof.reservation->'scope'->>'agent_id'
   AND b.agent_version_id=proof.reservation->'scope'->>'agent_version_id'
   AND b.run_id=proof.reservation->>'run_id'
   AND b.request_id=proof.reservation->>'request_id'
   AND b.request_fingerprint=proof.reservation->>'fingerprint'
   AND b.price_version_id=proof.reservation->>'price_version_id'
 ))`), string(raw)).Scan(&confirmed)
	return confirmed, err
}

var _ ModelBudgetClosureReader = (*SQLStore)(nil)
