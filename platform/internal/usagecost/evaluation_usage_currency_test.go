package usagecost

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestEvaluationUsageRequiresExactSingleCurrencySettlementProof(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx := context.Background()
	prices := modelgovernance.NewSQLStore(store.db)
	if err := store.SetEvaluationPriceCurrencyReader(prices); err != nil {
		t.Fatal(err)
	}
	if err := prices.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := uniqueBudgetSuffix(t)
	for i, tc := range []struct {
		name         string
		currencies   []string
		unpriced     bool
		mismatched   bool
		wantCurrency string
		wantCost     int64
		wantUnpriced int64
	}{
		{name: "USD", currencies: []string{"USD", "USD"}, wantCurrency: "USD", wantCost: 10},
		{name: "mixed", currencies: []string{"USD", "CNY"}},
		{name: "missing", currencies: []string{"USD", "USD"}, unpriced: true, wantUnpriced: 1},
		{name: "mismatched-cost", currencies: []string{"USD"}, mismatched: true, wantUnpriced: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := validBudgetTestRequest(now, fmt.Sprintf("eval-%s-%d", suffix, i), fmt.Sprintf("eval-%s-%d", suffix, i), 100, 5)
			for j, currency := range tc.currencies {
				priceID := fmt.Sprintf("eval-%s-%d-%d", suffix, i, j)
				_, err := store.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_price_version(id,model_version_id,currency,input_micros_per_1k_tokens,output_micros_per_1k_tokens,effective_from,content_hash,status,revision,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), priceID, "eval-"+suffix, currency, 1, 1, now, fmt.Sprintf("sha256:%064d", i*10+j), "approved", 1, "fixture", now, now)
				if err != nil {
					t.Fatal(err)
				}
				request.PriceVersionID = priceID
				request.RequestID = fmt.Sprintf("eval-event-%s-%d-%d", suffix, i, j)
				request.Fingerprint = fingerprintFor(request.RequestID)
				event := Event{ID: request.RequestID, Scope: budgetUsageScope(request), Provider: "fixture", Model: "fixture", InputTokens: 2, OutputTokens: 1, CostMicros: 5}
				if tc.unpriced && j == 1 {
					_, err = store.Apply(ctx, event)
				} else {
					var reservation ModelBudgetReservation
					reservation, err = store.Reserve(ctx, request)
					if err == nil {
						_, err = store.Settle(ctx, reservation, event, priceID)
					}
					if err == nil && tc.mismatched {
						_, err = store.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_budget_settlement SET settled_micros=6 WHERE reservation_id=?`), reservation.ReservationID)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := store.EvaluationUsage(ctx, budgetUsageScope(request), now.Add(-time.Minute), now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if result.EventCount != int64(len(tc.currencies)) || result.InputTokens != int64(len(tc.currencies)*2) || result.Currency != tc.wantCurrency || result.CostMicros != tc.wantCost || result.Unpriced != tc.wantUnpriced || result.Unsettled != 0 {
				t.Fatalf("wrong cost provenance: %+v", result)
			}
		})
	}
}

type currencyReadFunc func(context.Context, *sql.Tx, string) (string, error)

func (f currencyReadFunc) HistoricalPriceCurrencyTx(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	return f(ctx, tx, id)
}

func TestEvaluationCurrencyPortSharesSnapshotAndFailsClosedPostgres(t *testing.T) {
	s := openModelBudgetSQLStore(t)
	ctx := context.Background()
	prices := modelgovernance.NewSQLStore(s.db)
	if err := prices.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := uniqueBudgetSuffix(t)
	priceID := "currency-snapshot-" + suffix
	_, err := s.db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_price_version(id,model_version_id,currency,input_micros_per_1k_tokens,output_micros_per_1k_tokens,effective_from,content_hash,status,revision,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), priceID, "fixture", "USD", 1, 1, now, fmt.Sprintf("sha256:%064d", 1), "approved", 1, "fixture", now, now)
	if err != nil {
		t.Fatal(err)
	}
	q := validBudgetTestRequest(now, "snapshot-"+suffix, "snapshot-"+suffix, 100, 5)
	q.PriceVersionID = priceID
	r, err := s.Reserve(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	event := Event{ID: q.RequestID, Scope: budgetUsageScope(q), Provider: "fixture", Model: "fixture", CostMicros: 5}
	if _, err := s.Settle(ctx, r, event, priceID); err != nil {
		t.Fatal(err)
	}
	read := func() (EvaluationUsageSummary, error) {
		return s.EvaluationUsage(ctx, budgetUsageScope(q), now.Add(-time.Minute), now.Add(time.Minute))
	}
	if _, err := read(); err == nil {
		t.Fatal("missing port accepted priced events")
	}
	s.priceCurrency = currencyReadFunc(func(ctx context.Context, tx *sql.Tx, id string) (string, error) {
		var mode string
		if err := tx.QueryRowContext(ctx, `SHOW transaction_read_only`).Scan(&mode); err != nil || mode != "on" {
			t.Fatalf("not read only: %s %v", mode, err)
		}
		if _, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_price_version SET currency='CNY' WHERE id=?`), id); err != nil {
			return "", err
		}
		return prices.HistoricalPriceCurrencyTx(ctx, tx, id)
	})
	result, err := read()
	if err != nil || result.Currency != "USD" || result.CostMicros != 5 {
		t.Fatalf("price read used a newer snapshot: %+v %v", result, err)
	}
	s.priceCurrency = prices
	result, err = read()
	if err != nil || result.Currency != "CNY" {
		t.Fatalf("new transaction lost historical currency: %+v %v", result, err)
	}
	sentinel := errors.New("price evidence unavailable")
	s.priceCurrency = currencyReadFunc(func(context.Context, *sql.Tx, string) (string, error) { return "", sentinel })
	if _, err := read(); !errors.Is(err, sentinel) {
		t.Fatalf("evidence error hidden: %v", err)
	}
	s.priceCurrency = currencyReadFunc(func(context.Context, *sql.Tx, string) (string, error) { return "usd", nil })
	if _, err := read(); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("invalid currency accepted: %v", err)
	}
	s.priceCurrency = currencyReadFunc(func(context.Context, *sql.Tx, string) (string, error) { return "", nil })
	result, err = read()
	if err != nil || result.Unpriced != 1 || result.Currency != "" || result.CostMicros != 0 {
		t.Fatalf("missing price invented a total: %+v %v", result, err)
	}
}
