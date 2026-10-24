package usagecost

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestBudgetRetentionRequiresFullNativeHoldPostgres(t *testing.T) {
	s := openModelBudgetSQLStore(t)
	ctx := context.Background()
	suffix := uniqueBudgetSuffix(t)
	r, err := s.Reserve(ctx, validBudgetTestRequest(time.Now().UTC(), "retention-"+suffix, "retention-"+suffix, 100, 7))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkReconciliationNeeded(ctx, r); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if ok, err := s.BudgetRetentionsConfirmedTx(ctx, tx, []ModelBudgetReservation{r}); err != nil || !ok {
		t.Fatal("native full hold rejected", ok, err)
	}
	for _, dimension := range []string{"amount", "fingerprint", "price", "scope", "run", "request", "identity"} {
		t.Run(dimension, func(t *testing.T) {
			changed := r
			switch dimension {
			case "amount":
				changed.ReserveMicros--
			case "fingerprint":
				changed.Fingerprint = fingerprintFor("different")
			case "price":
				changed.PriceVersionID = "other"
			case "scope":
				changed.Scope.ApplicationID = "other"
			case "run":
				changed.RunID = "other"
			case "request":
				changed.RequestID = "other"
			case "identity":
				changed.ReservationID = "other"
			}
			if ok, err := s.BudgetRetentionsConfirmedTx(ctx, tx, []ModelBudgetReservation{changed}); err != nil || ok {
				t.Fatal("substituted hold accepted", ok, err)
			}
		})
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Synthetic fixture has no provider charge. A released reservation is no
	// longer proof of retained exposure, even though its immutable amount remains.
	if err := s.ResolveUncharged(ctx, r, "owned-retention-fixture-no-charge-"+suffix); err != nil {
		t.Fatal(err)
	}
	tx, err = s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if ok, err := s.BudgetRetentionsConfirmedTx(ctx, tx, []ModelBudgetReservation{r}); err != nil || ok {
		t.Fatal("released reservation accepted as retained hold", ok, err)
	}
}
