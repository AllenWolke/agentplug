package capability

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type cacheModelAccess struct {
	modelAccessResolverFunc
	mode string
}

func TestKnowledgePackingIncludesExactCachePartitionBeforeModelAdmission(t *testing.T) {
	r := governedInvocationResolver()
	r.snapshot.Model.ContextCache = &policyasset.ContextCachePolicy{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "session"}
	messages := []modelgateway.Message{{Role: "system", Content: r.snapshot.Prompt.Template}, {Role: "user", Content: "bounded passage"}}
	r.snapshot.Model.MaxTokens = 128
	r.snapshot.Model.MaxInputTokens = contextInputEstimate(messages, r.snapshot.Tool, nil, true)
	op := envelope{Policy: r.snapshot, Context: capabilityContext()}
	m := &Module{signingSecret: "long-unit-signing-secret"}
	if ValidateModelContextLimit(op.Policy.Model, messages, op.Policy.Tool, nil, true) != nil {
		t.Fatal("bare packing condition invalid")
	}
	if m.knowledgeModelInputFits(op)(messages, true) {
		t.Fatal("cache prefix omitted from preflight")
	}
	wire, _, err := m.invocationContext(op, messages, false)
	if err != nil {
		t.Fatal(err)
	}
	op.Policy.Model.MaxInputTokens = contextInputEstimate(wire, op.Policy.Tool, nil, true)
	if !m.knowledgeModelInputFits(op)(messages, true) || m.modelGateway != nil || m.modelBudgets != nil {
		t.Fatal("exact fit rejected or preflight needs provider/accounting")
	}
}

func (a cacheModelAccess) ResolveRoutingModel(ctx context.Context, scope sharedkernel.Scope, id string) (modelgateway.RoutingMetadata, error) {
	selection, err := a.ResolveModel(ctx, scope, id)
	return modelgateway.RoutingMetadata{Selection: selection, Kind: "chat", ContextLimit: 131072, ContextCacheMode: a.mode}, err
}

func TestContextPrefixHTTPSettlementReplayAndReceiptLookup(t *testing.T) {
	rate, hit, miss := int64(100), 750, 250
	resolver := governedInvocationResolver()
	resolver.snapshot.Model.ContextCache = &policyasset.ContextCachePolicy{Version: "context-prefix/v1", Mode: "provider_prefix", Isolation: "session"}
	prices := testApprovedPriceResolver()
	prices.price.InputMicrosPer1K, prices.price.OutputMicrosPer1K, prices.price.CachedInputMicrosPer1K = 400, 800, &rate
	budgets := &captureModelBudgetStore{}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "fresh diagnosis", InputTokens: 1000, OutputTokens: 10,
		CacheUsage: modelgateway.CacheUsage{CachedInputTokens: &hit, UncachedInputTokens: &miss}}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "long-unit-signing-secret", nil, "platform", "agent-runtime", nil, resolver)
	module.SetGovernedModelInvocation(cacheModelAccess{fixedModelAccess(), "provider_prefix"}, gateway)
	module.SetModelBilling(prices, budgets)
	module.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "cache-call", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	first := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"cost_micros":183`) || !strings.Contains(first.Body.String(), `"cached_input_tokens":750`) || !strings.Contains(first.Body.String(), `"cache_savings_micros":225`) {
		t.Fatalf("cache billing response=%d %s", first.Code, first.Body.String())
	}
	if len(gateway.request.Messages) != 2 || !strings.Contains(gateway.request.Messages[0].Content, "Context partition") || gateway.request.Messages[1].Content != "hello" {
		t.Fatal("namespace not sent or conversation changed")
	}
	if len(budgets.reserved) != 1 || budgets.reserved[0].ReserveMicros <= 183 || len(budgets.settled) != 1 || budgets.settled[0].InputTokens != 1000 || budgets.settled[0].CostMicros != 183 {
		t.Fatal("budget or ledger counted cache twice")
	}
	second := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
	if second.Code != http.StatusOK || first.Body.String() != second.Body.String() || gateway.calls != 1 || len(budgets.settled) != 1 {
		t.Fatal("replay reissued or recharged")
	}
	query := capabilityRequest(t, module, "/internal/model/receipt", capabilityContext(), input)
	if query.Code != http.StatusOK || !strings.Contains(query.Body.String(), `"status":"completed"`) || gateway.calls != 1 {
		t.Fatalf("original-command lookup failed: %d %s", query.Code, query.Body.String())
	}
}

func TestPreparationOnlyPrefixKeepsLocalReplayAndMissingUsageHonest(t *testing.T) {
	resolver := governedInvocationResolver()
	resolver.snapshot.Model.ContextCache = &policyasset.ContextCachePolicy{Version: "context-prefix/v2", Mode: "provider_prefix", Isolation: "session", UnsupportedModelBehavior: "prepare_prefix"}
	budgets := &captureModelBudgetStore{}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "fresh local answer", InputTokens: 1000, OutputTokens: 10}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "long-unit-signing-secret", nil, "platform", "agent-runtime", nil, resolver)
	module.SetGovernedModelInvocation(cacheModelAccess{fixedModelAccess(), ""}, gateway)
	module.SetModelBilling(testApprovedPriceResolver(), budgets)
	module.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "preparation-only", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	first := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "fresh local answer") || strings.Contains(first.Body.String(), `"cached_input_tokens":0`) || strings.Contains(first.Body.String(), `"cache_savings_micros":0`) {
		t.Fatalf("preparation invented usage: %d %s", first.Code, first.Body.String())
	}
	if len(gateway.request.Messages) != 2 || !strings.Contains(gateway.request.Messages[0].Content, "Context partition") || gateway.request.Messages[1].Content != "hello" {
		t.Fatal("prefix preparation or transcript lost")
	}
	second := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
	lookup := capabilityRequest(t, module, "/internal/model/receipt", capabilityContext(), input)
	if second.Code != http.StatusOK || first.Body.String() != second.Body.String() || lookup.Code != http.StatusOK || !strings.Contains(lookup.Body.String(), `"status":"completed"`) || gateway.calls != 1 || len(budgets.settled) != 1 {
		t.Fatal("preparation-only replay changed identity or rebilled")
	}
}

func TestCachePricedMissingUsageRetainsUnknownWithoutResend(t *testing.T) {
	prices := testApprovedPriceResolver()
	rate := int64(0)
	prices.price.CachedInputMicrosPer1K = &rate
	budgets := &captureModelBudgetStore{}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "known text", InputTokens: 1000, OutputTokens: 10}}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelBilling(prices, budgets)
	module.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "unknown-cache-usage", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	for i := 0; i < 2; i++ {
		response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
		if response.Code != 502 && response.Code != 409 {
			t.Fatalf("unknown cache cost disclosed: %d %s", response.Code, response.Body.String())
		}
	}
	if gateway.calls != 1 || len(budgets.settled) != 0 || len(budgets.released) != 0 || len(budgets.reconciled) == 0 {
		t.Fatal("unknown cache cost was sent/settled/released again")
	}
}

func TestCacheWeightedRoundingColdBudgetAndOverflow(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		input, output, rate, cachedRate int64
		hit                             int
		want                            int64
	}{
		{1000, 10, 400, 100, 750, 183}, {1, 0, 1, 1, 1, 1}, {2, 0, 1, 1, 1, 1},
		{1000, 0, 400, 0, 1000, 0}, {1000, 0, 400, 100, 0, 400},
	} {
		price := modelgovernance.PriceVersion{InputMicrosPer1K: tc.rate, OutputMicrosPer1K: 800, CachedInputMicrosPer1K: &tc.cachedRate}
		cost, err := approvedModelCacheCost(price, tc.input, tc.output, &tc.hit)
		if err != nil || cost != tc.want {
			t.Fatalf("weighted cost=%d want=%d error=%v", cost, tc.want, err)
		}
		cold, err := approvedModelCost(price, tc.input, tc.output)
		if err != nil || cost > cold {
			t.Fatal("discount exceeded cold admission")
		}
	}
	rate := int64(1)
	price := modelgovernance.PriceVersion{InputMicrosPer1K: 2, CachedInputMicrosPer1K: &rate}
	if _, err := approvedModelCacheCost(price, 10, 0, nil); err == nil {
		t.Fatal("missing measured split accepted")
	}
	if _, err := approvedModelCacheCost(price, math.MaxInt64, 0, &zero); err == nil {
		t.Fatal("overflow accepted")
	}
	price.CachedInputMicrosPer1K = nil
	if cost, err := approvedModelCacheCost(price, 1000, 0, nil); err != nil || cost != 2 {
		t.Fatal("uniform historical tariff changed")
	}
	encoded, _ := json.Marshal(price)
	if strings.Contains(string(encoded), "cached_input_micros") {
		t.Fatal("nil tariff changed legacy payload")
	}
}

func TestUnreportedCacheSplitWithEqualRatesHasExactCostWithoutInventedHits(t *testing.T) {
	for _, rate := range []int64{0, 100, 1000} {
		p := modelgovernance.PriceVersion{InputMicrosPer1K: rate, OutputMicrosPer1K: rate, CachedInputMicrosPer1K: &rate}
		got, err := approvedModelCacheCost(p, 239, 23, nil)
		want, plainErr := approvedModelCost(p, 239, 23)
		if err != nil || plainErr != nil || got != want {
			t.Fatal("determinate money treated as unknown", got, want, err)
		}
		invalid := 240
		if _, err := approvedModelCacheCost(p, 239, 23, &invalid); err == nil {
			t.Fatal("reported invalid split accepted")
		}
	}
	rate := int64(0)
	if _, err := approvedModelCacheCost(modelgovernance.PriceVersion{InputMicrosPer1K: 100, CachedInputMicrosPer1K: &rate}, 239, 23, nil); err == nil {
		t.Fatal("differential missing split was guessed")
	}
}
