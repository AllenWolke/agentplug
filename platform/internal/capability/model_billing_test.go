package capability

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type fixedModelPriceResolver struct {
	price modelgovernance.PriceVersion
	err   error
	calls int
}

func TestParentedModelUsageKeepsActorRun(t *testing.T) {
	h := capabilityContext()
	h.TaskID = "evaluation-case-run"
	h.ParentRunID = "evaluation-parent-run"
	if got := runtimeUsageRunID(h); got != h.TaskID {
		t.Fatalf("model usage run=%q, want actor run=%q", got, h.TaskID)
	}
	event, err := buildModelUsageEvent(h, modelgateway.Selection{}, 2, 1, 3, "case-idempotency")
	if err != nil || event.Scope.RunID != h.TaskID {
		t.Fatalf("usage event=%+v err=%v", event, err)
	}
	h.ParentRunID = ""
	if got := runtimeUsageRunID(h); got != h.TaskID {
		t.Fatalf("ordinary run lost its canonical execution identity: %q", got)
	}
	event, err = buildModelUsageEvent(h, modelgateway.Selection{}, 2, 1, 3, "ordinary-call")
	if err != nil || event.Scope.RunID != h.TaskID {
		t.Fatalf("ordinary usage identity: %+v %v", event, err)
	}
}

func (r *fixedModelPriceResolver) ResolvePrice(_ context.Context, versionID string, at time.Time) (modelgovernance.PriceVersion, error) {
	r.calls++
	if versionID != r.price.ModelVersionID || at.Before(r.price.EffectiveFrom) {
		return modelgovernance.PriceVersion{}, modelgovernance.ErrNotFound
	}
	return r.price, r.err
}

type captureModelBudgetStore struct {
	reserved        []usagecost.ModelBudgetRequest
	settled         []usagecost.Event
	settledPriceIDs []string
	settleCalls     int
	released        []usagecost.ModelBudgetReservation
	reconciled      []usagecost.ModelBudgetReservation
	reserveErr      error
	settleErr       error
	holdErr         error
}

func (s *captureModelBudgetStore) Reserve(_ context.Context, request usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	s.reserved = append(s.reserved, request)
	if s.reserveErr != nil {
		return usagecost.ModelBudgetReservation{}, s.reserveErr
	}
	return usagecost.ModelBudgetReservation{
		ReservationID: "reservation-1", Scope: request.Scope, RunID: request.RunID, Window: request.Window,
		RequestID: request.RequestID, Fingerprint: request.Fingerprint, PriceVersionID: request.PriceVersionID,
		BudgetLimitMicros: request.BudgetLimitMicros, ReserveMicros: request.ReserveMicros, ExpiresAt: request.ExpiresAt,
		Status: "pending",
	}, nil
}

func (s *captureModelBudgetStore) Settle(_ context.Context, _ usagecost.ModelBudgetReservation, event usagecost.Event, priceVersionID string) (usagecost.Snapshot, error) {
	s.settleCalls++
	if s.settleErr != nil {
		return usagecost.Snapshot{}, s.settleErr
	}
	s.settled = append(s.settled, event)
	s.settledPriceIDs = append(s.settledPriceIDs, priceVersionID)
	return usagecost.Snapshot{ScopeKey: usagecost.ScopeKey(event.Scope), LastEventID: event.ID}, nil
}

func (s *captureModelBudgetStore) Release(_ context.Context, reservation usagecost.ModelBudgetReservation) error {
	s.released = append(s.released, reservation)
	return nil
}

func (s *captureModelBudgetStore) MarkReconciliationNeeded(_ context.Context, reservation usagecost.ModelBudgetReservation) error {
	s.reconciled = append(s.reconciled, reservation)
	return s.holdErr
}

func (s *captureModelBudgetStore) ResolveUncharged(_ context.Context, reservation usagecost.ModelBudgetReservation, _ string) error {
	s.released = append(s.released, reservation)
	return nil
}

func testApprovedPriceResolver() *fixedModelPriceResolver {
	return &fixedModelPriceResolver{price: modelgovernance.PriceVersion{
		ID: "price-usd-v1", ModelVersionID: "version-a", Currency: "USD",
		InputMicrosPer1K: 1, OutputMicrosPer1K: 2,
		EffectiveFrom: time.Now().UTC().Add(-time.Hour), Status: modelgovernance.StatusApproved, Revision: 1,
		ContentHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}
}

func TestModelGenerationFailsClosedForMissingOrUnsupportedApprovedPrice(t *testing.T) {
	for name, mutate := range map[string]func(*fixedModelPriceResolver){
		"missing":        func(resolver *fixedModelPriceResolver) { resolver.err = modelgovernance.ErrNotFound },
		"wrong-currency": func(resolver *fixedModelPriceResolver) { resolver.price.Currency = "EUR" },
		"draft":          func(resolver *fixedModelPriceResolver) { resolver.price.Status = modelgovernance.StatusDraft },
	} {
		t.Run(name, func(t *testing.T) {
			prices := testApprovedPriceResolver()
			mutate(prices)
			gateway := &captureModelGateway{}
			module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
			module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
			module.SetModelBilling(prices, &captureModelBudgetStore{})
			response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{
				"idempotency_key": "missing-price-" + name, "prompt_template_hash": "prompt-hash",
				"messages": []map[string]string{{"role": "user", "content": "hello"}},
			})
			if response.Code != http.StatusServiceUnavailable || gateway.calls != 0 || !strings.Contains(response.Body.String(), "MODEL_PRICE_UNAVAILABLE") {
				t.Fatalf("invalid price must fail before provider: status=%d calls=%d body=%s", response.Code, gateway.calls, response.Body.String())
			}
		})
	}
}

func TestModelGenerationRejectsBudgetBeforeProviderAndUsesUSDUTCWindow(t *testing.T) {
	prices := testApprovedPriceResolver()
	budgets := &captureModelBudgetStore{reserveErr: usagecost.ErrBudgetExceeded}
	gateway := &captureModelGateway{}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelBilling(prices, budgets)
	capacity := &captureModelCapacity{}
	module.SetModelCapacity(capacity)
	response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{
		"idempotency_key": "budget-rejected", "prompt_template_hash": "prompt-hash",
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if response.Code != http.StatusPaymentRequired || gateway.calls != 0 || len(budgets.reserved) != 1 {
		t.Fatalf("budget rejection must happen before provider: status=%d calls=%d reservations=%d body=%s", response.Code, gateway.calls, len(budgets.reserved), response.Body.String())
	}
	request := budgets.reserved[0]
	if request.BudgetLimitMicros != math.MaxInt64 || request.Window.Start.Location() != time.UTC || request.Window.Start.Hour() != 0 || request.Window.End.Sub(request.Window.Start) != 24*time.Hour || request.PriceVersionID != "price-usd-v1" {
		t.Fatalf("unbounded legacy policy budget must use bounded USD/day rule: %+v", request)
	}
}

type retryingBudgetStore struct {
	captureModelBudgetStore
	script []error
}

func (s *retryingBudgetStore) Reserve(ctx context.Context, request usagecost.ModelBudgetRequest) (usagecost.ModelBudgetReservation, error) {
	s.reserved = append(s.reserved, request)
	if len(s.script) > 0 {
		err := s.script[0]
		s.script = s.script[1:]
		if err != nil {
			return usagecost.ModelBudgetReservation{}, err
		}
	}
	s.reserveErr = nil
	return s.captureModelBudgetStore.Reserve(ctx, request)
}

func TestModelBudgetLockWaitIsDeferredNotLedgerUnavailable(t *testing.T) {
	prices := testApprovedPriceResolver()
	budgets := &retryingBudgetStore{script: []error{context.DeadlineExceeded, context.DeadlineExceeded, context.DeadlineExceeded}}
	gateway := &captureModelGateway{}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelBilling(prices, budgets)
	response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{
		"idempotency_key": "budget-lock-wait", "prompt_template_hash": "prompt-hash",
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if response.Code != http.StatusServiceUnavailable || gateway.calls != 0 || len(budgets.reserved) != 3 || !strings.Contains(response.Body.String(), "MODEL_BUDGET_ADMISSION_DEFERRED") || strings.Contains(response.Body.String(), "MODEL_BUDGET_UNAVAILABLE") {
		t.Fatalf("ancestor lock wait must not be reported as a ledger outage: status=%d calls=%d reservations=%d body=%s", response.Code, gateway.calls, len(budgets.reserved), response.Body.String())
	}
}

func TestPositivePolicyBudgetIsConvertedToUSDmicrosAndReservedAtResolvedRates(t *testing.T) {
	price := testApprovedPriceResolver().price
	price.InputMicrosPer1K, price.OutputMicrosPer1K = 10_000, 20_000
	now := time.Now().UTC()
	request, err := buildModelBudgetRequest(capabilityContext(), []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{{Role: "user", Content: "hello"}}, 10, 123, price, strings.Repeat("a", 64), "attempt-1", now, 60)
	if err != nil {
		t.Fatal(err)
	}
	if request.BudgetLimitMicros != 1_230_000 || request.ReserveMicros != 330 {
		t.Fatalf("policy budget or approved rates were not applied: limit=%d reserve=%d", request.BudgetLimitMicros, request.ReserveMicros)
	}
}

func TestKnownProviderResultWithSettlementFailureRequiresReconciliation(t *testing.T) {
	prices := testApprovedPriceResolver()
	budgets := &captureModelBudgetStore{settleErr: errors.New("usage SQL unavailable")}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "known answer", InputTokens: 12, OutputTokens: 4}}
	capacity := &captureModelCapacity{}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelBilling(prices, budgets)
	module.SetModelCapacity(capacity)
	ctx := capabilityContext()
	input := map[string]any{"idempotency_key": "reconcile-known-result", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	response := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "MODEL_RECONCILIATION_REQUIRED") || gateway.calls != 1 || len(budgets.released) != 0 || len(budgets.reconciled) != 2 || budgets.settleCalls != 1 || len(capacity.requests) != 1 || len(capacity.released) != 1 {
		t.Fatalf("known provider result must remain billable and unreleased: status=%d calls=%d released=%d held=%d settle_calls=%d body=%s", response.Code, gateway.calls, len(budgets.released), len(budgets.reconciled), budgets.settleCalls, response.Body.String())
	}
	record := module.modelStore.(*memoryModelInvocationStore).records[capabilityScopeHash(ctx)+"\x00reconcile-known-result"]
	if record.Status != "reconcile" || record.Response["text"] != "known answer" || record.CostCents == 0 {
		t.Fatalf("known result was not durably marked for reconciliation: %+v", record)
	}
	replay := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if replay.Code != http.StatusConflict || !strings.Contains(replay.Body.String(), "MODEL_RECONCILIATION_REQUIRED") || gateway.calls != 1 || len(budgets.reserved) != 1 {
		t.Fatalf("reconciliation retry must not invoke provider again: status=%d calls=%d reservations=%d body=%s", replay.Code, gateway.calls, len(budgets.reserved), replay.Body.String())
	}
}

func TestDefiniteProviderFailureReleasesBudgetAndAllowsIdempotentRetry(t *testing.T) {
	budgets := &captureModelBudgetStore{}
	capacity := &captureModelCapacity{}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), &captureModelGateway{err: modelgateway.ErrModelUnavailable})
	module.SetModelBilling(testApprovedPriceResolver(), budgets)
	module.SetModelCapacity(capacity)
	ctx := capabilityContext()
	input := map[string]any{"idempotency_key": "definite-retry", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	failed := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if failed.Code != http.StatusBadGateway || len(budgets.released) != 1 {
		t.Fatalf("definite pre-provider failure must release reservation: status=%d released=%d body=%s", failed.Code, len(budgets.released), failed.Body.String())
	}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "retry answer", InputTokens: 2, OutputTokens: 2}}
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelCapacity(capacity)
	completed := capabilityRequest(t, module, "/internal/model/generate", ctx, input)
	if completed.Code != http.StatusOK || gateway.calls != 1 || len(budgets.reserved) != 2 || budgets.settleCalls != 1 || len(capacity.requests) != 2 || len(capacity.released) != 2 {
		t.Fatalf("released idempotency key should retry with a fresh budget reservation: status=%d calls=%d reservations=%d settles=%d body=%s", completed.Code, gateway.calls, len(budgets.reserved), budgets.settleCalls, completed.Body.String())
	}
	if budgets.reserved[0].RequestID == budgets.reserved[1].RequestID {
		t.Fatal("each retry attempt must own a distinct reservation id while invocation idempotency stays stable")
	}
}

func TestModelCapacityExceededStopsProviderAndReleasesBudgetReservation(t *testing.T) {
	budgets := &captureModelBudgetStore{}
	capacity := &captureModelCapacity{err: modelcapacity.ErrExceeded}
	gateway := &captureModelGateway{}
	module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	module.SetModelBilling(testApprovedPriceResolver(), budgets)
	module.SetModelCapacity(capacity)
	response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), map[string]any{
		"idempotency_key": "capacity-full", "prompt_template_hash": "prompt-hash",
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if response.Code != http.StatusTooManyRequests || gateway.calls != 0 || len(capacity.requests) != 1 || len(capacity.released) != 0 || len(budgets.released) != 1 {
		t.Fatalf("capacity admission did not fail before model execution: status=%d calls=%d acquired=%d released_capacity=%d released_budget=%d body=%s", response.Code, gateway.calls, len(capacity.requests), len(capacity.released), len(budgets.released), response.Body.String())
	}
}

func fixedModelAccess() modelAccessResolverFunc {
	return func(_ context.Context, _ sharedkernel.Scope, _ string) (modelgateway.Selection, error) {
		return modelgateway.Selection{ModelVersionID: "version-a", ProviderID: "provider-id-a", ProviderKey: "provider-a", ModelID: "model-id-a", ModelKey: "chat-model-a", TrustZone: modelgovernance.TrustLocal, DeploymentID: "deployment-a", EndpointRef: "service://local-model", CapacityUnits: 4}, nil
	}
}
