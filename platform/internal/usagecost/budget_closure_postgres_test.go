package usagecost

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestBudgetClosureUsesExactReservationAndOneSnapshotPostgres(t *testing.T) {
	s := openModelBudgetSQLStore(t)
	ctx := context.Background()
	suffix := uniqueBudgetSuffix(t)
	r, err := s.Reserve(ctx, validBudgetTestRequest(time.Now().UTC(), "closure-"+suffix, "closure-"+suffix, 100, 5))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	proof := ModelBudgetClosure{Reservation: r, Status: "released"}
	if ok, err := s.BudgetClosuresConfirmedTx(ctx, tx, []ModelBudgetClosure{proof}); err != nil || ok {
		t.Fatalf("live reservation accepted: %v %v", ok, err)
	}
	if err := s.Release(ctx, r); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.BudgetClosuresConfirmedTx(ctx, tx, []ModelBudgetClosure{proof}); err != nil || ok {
		t.Fatalf("snapshot changed after external release: %v %v", ok, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx, err = s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if ok, err := s.BudgetClosuresConfirmedTx(ctx, tx, []ModelBudgetClosure{proof}); err != nil || !ok {
		t.Fatalf("closed proof rejected: %v %v", ok, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ModelBudgetClosure)
	}{
		{"fingerprint", func(p *ModelBudgetClosure) { p.Reservation.Fingerprint = fingerprintFor("other") }},
		{"price", func(p *ModelBudgetClosure) { p.Reservation.PriceVersionID = "other-price" }},
		{"tenant", func(p *ModelBudgetClosure) { p.Reservation.Scope.TenantID = "other-tenant" }},
		{"run", func(p *ModelBudgetClosure) { p.Reservation.RunID = "other-run" }},
		{"request", func(p *ModelBudgetClosure) { p.Reservation.RequestID = "other-request" }},
		{"status", func(p *ModelBudgetClosure) { p.Status = "settled" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := proof
			tc.mutate(&changed)
			if ok, err := s.BudgetClosuresConfirmedTx(ctx, tx, []ModelBudgetClosure{changed}); err != nil || ok {
				t.Fatalf("substituted proof accepted: %v %v", ok, err)
			}
		})
	}
	if ok, err := s.BudgetClosuresConfirmedTx(ctx, tx, []ModelBudgetClosure{proof, {Reservation: r, Status: "settled"}}); err != nil || ok {
		t.Fatalf("partial closure accepted: %v %v", ok, err)
	}
}
