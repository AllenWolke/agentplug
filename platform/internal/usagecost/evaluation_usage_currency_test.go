package usagecost

import (
	"context"
	"fmt"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestEvaluationUsageRequiresExactSingleCurrencySettlementProof(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	ctx := context.Background()
	if err := modelgovernance.NewSQLStore(store.db).EnsureSchema(ctx); err != nil {
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
