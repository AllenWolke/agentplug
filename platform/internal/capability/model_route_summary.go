package capability

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func routeSummaryReceipt(stored StoredModelRoute, invocation ModelInvocation, found bool) (policyasset.ModelRoutingReceipt, error) {
	d := stored.Decision
	out := policyasset.ModelRoutingReceipt{DecisionSHA256: stored.DecisionSHA256, ModelVersionID: d.ModelVersionID,
		QualificationReuse: d.QualificationReuse,
		ModelKey:           d.ModelKey,
		PriceVersionID:     d.Price.ID, Complexity: d.Features.Complexity, Reasons: append([]string(nil), d.Features.Reasons...),
		EstimatedMicros: d.EstimatedMicros, InvocationStatus: "not_admitted"}
	if d.Fallback != nil {
		out.FallbackAttempt, out.PreviousDecisionSHA256 = d.Fallback.Attempt, d.Fallback.PreviousDecisionSHA256
	}
	if found {
		out.InvocationStatus = invocation.Status
		if invocation.Status == "completed" {
			// Only a finalized public ledger receipt supplies actual cost. An estimate
			// or uncertain request must never appear as zero-cost completion.
			raw, err := json.Marshal(invocation.Response["billing"])
			var billing struct {
				PriceVersionID string `json:"price_version_id"`
				Currency       string `json:"currency"`
				CostMicros     *int64 `json:"cost_micros"`
			}
			if err != nil || json.Unmarshal(raw, &billing) != nil || billing.PriceVersionID != d.Price.ID || billing.Currency != "USD" || billing.CostMicros == nil || *billing.CostMicros < 0 {
				return policyasset.ModelRoutingReceipt{}, ErrModelRouteUnavailable
			}
			out.ActualCostMicros = billing.CostMicros
		}
	}
	return out, nil
}

func (s *SQLModelInvocationStore) ReadRunModelRouting(ctx context.Context, scope sharedkernel.Scope) (policyasset.RunModelRoutingSummary, error) {
	out := policyasset.RunModelRoutingSummary{Version: "run-model-routing/v1", Mode: "manual", Decisions: []policyasset.ModelRoutingReceipt{}}
	binding, found, err := s.LookupModelSelection(ctx, scope)
	if err != nil {
		return out, err
	}
	if !found {
		return out, nil
	}
	out.Mode = binding.Selection.EffectiveMode()
	// Manual v2 can publish an explicit fallback pool. Legacy manual runs have
	// no route rows and naturally return an empty decision list.
	hash := modelSelectionScopeHash(scope)
	rows, err := s.db.QueryContext(ctx, sqlutil.Bind(`SELECT idempotency_key FROM platform_model_route_decision WHERE scope_hash=? ORDER BY created_at,idempotency_key LIMIT 65`), hash)
	if err != nil {
		return out, err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return out, err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(keys) > 64 {
		out.Truncated, keys = true, keys[:64]
	}
	for _, key := range keys {
		route, found, err := s.LookupModelRoute(ctx, hash, key)
		if err != nil || !found {
			return out, ErrModelRouteUnavailable
		}
		invocation, found, err := s.LookupModelInvocation(ctx, hash, key)
		if err != nil {
			return out, err
		}
		receipt, err := routeSummaryReceipt(route, invocation, found)
		if err != nil {
			return out, err
		}
		out.Decisions = append(out.Decisions, receipt)
	}
	return out, nil
}

var _ policyasset.ModelRoutingSummaryReader = (*SQLModelInvocationStore)(nil)
