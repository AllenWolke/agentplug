package usagecost

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
)

// Only a persisted, authorized provider no-charge receipt releases an unknown hold.
// 仅允许持久化且已授权的厂商未计费回执释放未知结果预占，不能按过期时间猜测。
type ModelBudgetManualReleaseStore interface {
	ResolveUncharged(context.Context, ModelBudgetReservation, string) error
}

func (s *SQLStore) ResolveUncharged(ctx context.Context, reservation ModelBudgetReservation, receipt string) error {
	if s == nil || s.db == nil {
		return errors.New("usage database is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.ResolveUnchargedTx(ctx, tx, reservation, receipt); err != nil {
		return err
	}
	return tx.Commit()
}

// ResolveUnchargedTx preserves terminal unbilled evidence in the caller-owned
// transaction. It neither commits nor accepts cancellation as billing proof.
func (s *SQLStore) ResolveUnchargedTx(ctx context.Context, tx *sql.Tx, reservation ModelBudgetReservation, receipt string) error {
	if s == nil || s.db == nil || tx == nil {
		return errors.New("usage database is required")
	}
	if strings.TrimSpace(receipt) == "" || len(receipt) > 256 {
		return ErrInvalidUsage
	}
	if err := validateReservationEnvelope(reservation); err != nil {
		return err
	}
	windowID, err := windowIDFromReservation(reservation)
	if err != nil {
		return err
	}
	window, err := lockBudgetWindowTx(ctx, tx, windowID)
	if err != nil {
		return err
	}
	stored, err := readBudgetReservationByIDTx(ctx, tx, reservation.ReservationID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBudgetReservationNotFound
	}
	if err != nil {
		return err
	}
	if stored.windowID != windowID || !sameReservationEnvelope(stored.reservation, reservation) {
		return ErrBudgetReservationConflict
	}
	digest := sha256.Sum256([]byte(receipt))
	receiptHash := hex.EncodeToString(digest[:])
	if stored.reservation.Status == "released" {
		var existingReason string
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT receipt_hash FROM platform_model_budget_manual_resolution WHERE reservation_id=?`), reservation.ReservationID).Scan(&existingReason); err != nil {
			return err
		}
		if existingReason != receiptHash {
			return ErrBudgetReservationConflict
		}
		return nil
	}
	if stored.reservation.Status != "reconcile" || window.ReservedMicros < stored.reservation.ReserveMicros {
		return ErrBudgetReservationClosed
	}
	now := s.modelBudgetNow()
	updated, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_window SET reserved_micros=reserved_micros-?,revision=revision+1,updated_at=? WHERE window_id=? AND reserved_micros>=?`), stored.reservation.ReserveMicros, now, windowID, stored.reservation.ReserveMicros)
	if err != nil {
		return err
	}
	if err := requireModelBudgetRow(updated); err != nil {
		return err
	}
	updated, err = tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_reservation SET status='released',terminal_reason='manual_no_charge',updated_at=?,released_at=? WHERE reservation_id=? AND status='reconcile'`), now, now, reservation.ReservationID)
	if err != nil {
		return err
	}
	if err := requireModelBudgetRow(updated); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_budget_manual_resolution(reservation_id,receipt_hash,created_at) VALUES(?,?,?)`), reservation.ReservationID, receiptHash, now); err != nil {
		return err
	}
	return nil
}
