package usagecost

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/sqlutil"
)

// LegacyModelAccountingAuthority verifies the original durable provider billing
// envelope. It grants no execution, model-result access or provider-send right.
type LegacyModelAccountingAuthority interface {
	VerifyLegacyAccountingTx(context.Context, *sql.Tx, ModelBudgetReservation, string, *Event, string, string) error
}

// An explicit operator allowlist is frozen BEFORE serving requests. Missing,
// future, corrupt or already tree-bound IDs reject startup; no missing-binding
// error can silently select the old accounting mode at runtime.
func (s *SQLRunTreeModelBudgetStore) freezeLegacyReservations(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	proof, ok := s.authority.(LegacyModelAccountingAuthority)
	if !ok || len(ids) > 128 {
		return ErrInvalidUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	frozen := make(map[string]ModelBudgetReservation, len(ids))
	for _, id := range ids {
		if !validModelBudgetID(id) {
			return ErrInvalidUsage
		}
		if _, duplicate := frozen[id]; duplicate {
			return ErrBudgetReservationConflict
		}
		// Read metadata first without a row lock; provider proof then window
		// accounting follows the existing model -> price-window lock order.
		stored, err := scanModelBudgetReservation(tx.QueryRowContext(ctx,
			sqlutil.Bind(reservationSelect+` WHERE r.reservation_id=?`), id))
		if err != nil {
			return err
		}
		reservation := stored.reservation
		if validateReservationEnvelope(reservation) != nil ||
			(reservation.Status != "reconcile" && reservation.Status != "settled" && reservation.Status != "released") {
			return ErrBudgetReservationConflict
		}
		if err = proof.VerifyLegacyAccountingTx(ctx, tx, reservation, "unknown", nil, "", ""); err != nil {
			return err
		}
		if err = s.assertLegacyUnboundTx(ctx, tx, reservation); err != nil {
			return err
		}
		frozen[id] = reservation
	}
	// This initialization is read-only: no backfilled root, new hold or DDL.
	if err = tx.Commit(); err != nil {
		return err
	}
	s.legacy = frozen
	return nil
}

func (s *SQLRunTreeModelBudgetStore) assertLegacyUnboundTx(ctx context.Context, tx *sql.Tx, r ModelBudgetReservation) error {
	var bound bool
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT
		EXISTS(SELECT 1 FROM platform_run_tree_model_binding WHERE binding_key=? OR reservation_id=?)
		OR EXISTS(SELECT 1 FROM platform_run_tree_budget_request WHERE run_id=? AND request_id=?)`),
		modelBindingKey(r.Scope, r.RunID, r.RequestID), r.ReservationID, r.RunID, r.RequestID).Scan(&bound)
	if err != nil {
		return err
	}
	if bound {
		return ErrBudgetReservationConflict
	}
	return nil
}

func (s *SQLRunTreeModelBudgetStore) accountLegacyTx(ctx context.Context, tx *sql.Tx, r ModelBudgetReservation, action string, event *Event, priceID, providerRef string, operation func(*sql.Tx) error) error {
	proof, ok := s.authority.(LegacyModelAccountingAuthority)
	if !ok {
		return ErrBudgetReservationConflict
	}
	if err := proof.VerifyLegacyAccountingTx(ctx, tx, r, action, event, priceID, providerRef); err != nil {
		return err
	}
	if err := s.assertLegacyUnboundTx(ctx, tx, r); err != nil {
		return err
	}
	// Existing window operations validate and lock the exact original envelope,
	// preserve unknown holds, and apply only known billing/no-charge evidence.
	if err := operation(tx); err != nil {
		return err
	}
	if err := s.assertLegacyUnboundTx(ctx, tx, r); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	audited := audit.Event{ID: "legacy-budget-" + hex.EncodeToString(nonce[:]),
		TenantID: r.Scope.TenantID, DepartmentID: r.Scope.DepartmentID, ApplicationID: r.Scope.ApplicationID,
		ActorType: "system", ActorID: "model-billing-reconciler", TraceID: "legacy-model-accounting",
		AggregateType: "model_budget_reservation", AggregateID: r.ReservationID,
		Action: "budget.legacy_" + action, Outcome: "success", Summary: "accounting-only; no execution or root-budget admission"}
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&audited.CreatedAt); err != nil {
		return err
	}
	if err := s.tree.audit.RecordTx(tx, audited); err != nil {
		return err
	}
	return tx.Commit()
}
