package capability

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type failoverGatewayFixture struct {
	calls           []modelgateway.GenerateRequest
	firstError      error
	firstIncomplete bool
	cancel          context.CancelFunc
}

func (g *failoverGatewayFixture) Generate(_ context.Context, _ sharedkernel.Scope, _ policyasset.Snapshot, request modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.calls = append(g.calls, request)
	if len(g.calls) == 1 {
		if g.cancel != nil {
			g.cancel()
		}
		if g.firstError != nil {
			return modelgateway.GenerateResult{}, g.firstError
		}
		if g.firstIncomplete {
			return modelgateway.GenerateResult{Text: "partial", InputTokens: 11, OutputTokens: 2, Incomplete: true, FinishReason: "length"}, nil
		}
	}
	return modelgateway.GenerateResult{Text: "complete", InputTokens: 11, OutputTokens: 2, FinishReason: "stop"}, nil
}
func (g *failoverGatewayFixture) Embed(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) ([][]float32, error) {
	return nil, modelgateway.ErrModelUnavailable
}

func failoverInvocationFixture(t *testing.T) (*Module, envelope, *failoverGatewayFixture, *captureModelBudgetStore) {
	t.Helper()
	m, op, _, _ := routeInvocationFixture(t)
	op.Policy.Model.BudgetCents = 100
	p := op.Policy.Model.Routing
	a := availabilityPolicy()
	p.Availability = &a
	// Capability equivalence is fixture evidence, not a claim about real models.
	for i := range p.Candidates {
		p.Candidates[i].MaxComplexity = "complex"
	}
	p.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(op.Policy)
	g := &failoverGatewayFixture{}
	b := &captureModelBudgetStore{}
	m.modelGateway, m.modelBudgets, m.modelCapacity = g, b, &captureModelCapacity{}
	op.Input, _ = json.Marshal(modelGenerateInput{IdempotencyKey: "logical-call", Messages: routeRequest("指标定义是什么").Messages, MaxTokens: 64})
	return m, op, g, b
}

func invokeFailover(m *Module, op envelope, ctx context.Context) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/internal/model/generate", nil).WithContext(ctx)
	m.generateAuthorized(w, r, op)
	return w
}

func TestRouteFailoverVerifiedUnsentUsesNewIdentityAndReplays(t *testing.T) {
	m, op, g, b := failoverInvocationFixture(t)
	g.firstError = modelgateway.ErrSecretUnavailable
	w := invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || g.calls[0].ModelVersionID == g.calls[1].ModelVersionID {
		t.Fatal("safe failure did not select another model", w.Code, w.Body.String(), len(g.calls))
	}
	if len(b.released) != 1 || len(b.settled) != 1 {
		t.Fatal("failed admission or successful charge lost")
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	first, _, err := store.LookupModelRoute(context.Background(), scope, "logical-call")
	if err != nil {
		t.Fatal(err)
	}
	second, found, err := store.LookupModelRoute(context.Background(), scope, physicalRouteAttemptKey("logical-call", 1))
	if err != nil || !found || second.Decision.Fallback == nil || second.Decision.Fallback.PreviousDecisionSHA256 != first.DecisionSHA256 {
		t.Fatal("attempt predecessor not durable", err)
	}
	w = invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || len(b.settled) != 1 {
		t.Fatal("logical replay resent or charged again", w.Code, w.Body.String())
	}
	// Read-only logical recovery reaches the final receipt and preserves caller key.
	w = httptest.NewRecorder()
	m.modelReceiptAuthorized(w, httptest.NewRequest("POST", "/internal/model/generate/receipt", nil), op, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"idempotency_key":"logical-call"`) || !strings.Contains(w.Body.String(), `"status":"completed"`) || len(g.calls) != 2 {
		t.Fatal("receipt lookup did not follow durable attempt chain", w.Code, w.Body.String())
	}
	var changed modelGenerateInput
	_ = json.Unmarshal(op.Input, &changed)
	changed.Messages = routeRequest("比较多个制度").Messages
	op.Input, _ = json.Marshal(changed)
	w = invokeFailover(m, op, context.Background())
	if w.Code != 409 || len(g.calls) != 2 {
		t.Fatal("changed logical input replayed", w.Code, w.Body.String())
	}
}

func TestRouteFailoverUnknownOutcomeRetainsOriginal(t *testing.T) {
	m, op, g, b := failoverInvocationFixture(t)
	g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	for i := 0; i < 2; i++ {
		w := invokeFailover(m, op, context.Background())
		if w.Code != http.StatusBadGateway && w.Code != http.StatusConflict {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(g.calls) != 1 || len(b.released) != 0 || len(b.settled) != 0 {
		t.Fatal("unknown response switched model, released or invented charge")
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	if _, found, _ := store.LookupModelRoute(context.Background(), scope, physicalRouteAttemptKey("logical-call", 1)); found {
		t.Fatal("unknown response created another route")
	}
	state, found, err := store.LookupModelAvailability(context.Background(), modelAvailabilityPartition(scopeFromHarness(op.Context)), g.calls[0].ModelVersionID)
	if err != nil || !found || state.OpenUntil.IsZero() {
		t.Fatal("future fresh requests cannot avoid failed provider", err)
	}
}

func TestRouteFailoverKnownIncompleteRetainsBothCharges(t *testing.T) {
	m, op, g, b := failoverInvocationFixture(t)
	g.firstIncomplete = true
	w := invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || len(b.settled) != 2 || b.settled[0].ID == b.settled[1].ID {
		t.Fatal("known incomplete call lost charge or used same physical identity", w.Code, w.Body.String())
	}
	w = invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || len(b.settled) != 2 {
		t.Fatal("replay repeated a known charge")
	}
}

func TestRouteFailoverCancellationStopsNextAttempt(t *testing.T) {
	m, op, g, b := failoverInvocationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.cancel = cancel
	g.firstIncomplete = true
	_ = invokeFailover(m, op, ctx)
	if len(g.calls) != 1 || len(b.settled) != 1 {
		t.Fatal("cancelled caller sent another attempt or dropped known billing")
	}
}

func TestRouteFailoverQualityFloorAndBounds(t *testing.T) {
	m, op, g, _ := failoverInvocationFixture(t)
	g.firstError = modelgateway.ErrSecretUnavailable
	p := op.Policy.Model.Routing
	for i := range p.Candidates {
		if p.Candidates[i].ModelVersionID != "small" {
			p.Candidates[i].MaxComplexity = "simple"
		}
	}
	// Primary model must retain a complex candidate in a valid policy; use the
	// initial high-tier local model as primary for this isolated fixture.
	op.Policy.Model.ModelVersionID = "small"
	op.Policy.Model.Model = "small"
	op.Policy.Model.Provider = "provider-small"
	p.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(op.Policy)
	var input modelGenerateInput
	_ = json.Unmarshal(op.Input, &input)
	input.Messages = routeRequest("比较多个制度的差异").Messages
	op.Input, _ = json.Marshal(input)
	w := invokeFailover(m, op, context.Background())
	if w.Code != 409 || !strings.Contains(w.Body.String(), "MODEL_ROUTE_NO_CANDIDATE") || len(g.calls) != 1 {
		t.Fatal("failed complex candidate downgraded", w.Code, w.Body.String())
	}
}
