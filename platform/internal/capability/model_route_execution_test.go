package capability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

func resilientInvocationFixture(t *testing.T) (*Module, envelope, *failoverGatewayFixture, *captureModelBudgetStore) {
	m, op, g, b := failoverInvocationFixture(t)
	op.Policy.Model.Routing.Availability.Version = "model-route-availability/v2"
	op.Policy.Model.Routing.Availability.UnknownOutcome = "retain_and_continue"
	op.Policy.Model.Routing.Availability.AttemptTimeoutSeconds = 10
	return m, op, g, b
}

type boundedFailureGateway struct {
	failoverGatewayFixture
	allFail           bool
	waitFirstDeadline bool
}

func (g *boundedFailureGateway) Generate(ctx context.Context, s sharedkernel.Scope, p policyasset.Snapshot, in modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	if g.allFail || g.waitFirstDeadline && len(g.calls) == 0 {
		g.calls = append(g.calls, in)
		if g.waitFirstDeadline {
			<-ctx.Done()
			return modelgateway.GenerateResult{}, &modelgateway.ProviderFailure{Category: "response_timeout"}
		}
		return modelgateway.GenerateResult{}, &modelgateway.ProviderFailure{Category: "body_read"}
	}
	return g.failoverGatewayFixture.Generate(ctx, s, p, in)
}

func TestRouteExecutionProviderDeadlineLeavesTimeForAlternate(t *testing.T) {
	m, op, _, b := resilientInvocationFixture(t)
	op.Policy.Model.Routing.Availability.AttemptTimeoutSeconds = 1
	g := &boundedFailureGateway{waitFirstDeadline: true}
	m.modelGateway = g
	started := time.Now()
	w := invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || len(b.released) != 0 || len(b.settled) != 1 || time.Since(started) > 2500*time.Millisecond {
		t.Fatal("first timeout consumed fallback allowance", w.Code, w.Body.String(), len(g.calls), time.Since(started))
	}
}

func TestRouteExecutionExhaustionIsDurableAndIndependentRunContinues(t *testing.T) {
	m, op, _, b := resilientInvocationFixture(t)
	g := &boundedFailureGateway{allFail: true}
	m.modelGateway = g
	w := invokeFailover(m, op, context.Background())
	if w.Code != 502 || !strings.Contains(w.Body.String(), "MODEL_ROUTE_ATTEMPTS_EXHAUSTED") || len(g.calls) != 3 || len(b.released) != 0 || len(b.settled) != 0 {
		t.Fatal(w.Code, w.Body.String(), len(g.calls))
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	state, found, err := store.LookupModelRouteExecution(context.Background(), modelSelectionScopeHash(scopeFromHarness(op.Context)), "logical-call")
	if err != nil || !found || state.Status != "exhausted" || len(state.Steps) != 3 {
		t.Fatal(state, err)
	}
	w = invokeFailover(m, op, context.Background())
	if w.Code != 502 || len(g.calls) != 3 {
		t.Fatal("exhausted execution restarted attempts", w.Code, w.Body.String())
	}
	// An unrelated application has its own availability and execution scope.
	// This represents another independent task with healthy approved providers.
	op.Context.ApplicationID = "independent-application"
	op.Context.TaskID = "independent-root"
	if err := store.BindModelSelection(context.Background(), scopeFromHarness(op.Context), policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
		t.Fatal(err)
	}
	g.allFail = false
	w = invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 4 {
		t.Fatal("failed execution blocked independent task", w.Code, w.Body.String(), len(g.calls))
	}
}

func TestRouteExecutionBindsOriginalParentDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		m, op, g, _ := resilientInvocationFixture(t)
		var in modelGenerateInput
		_ = json.Unmarshal(op.Input, &in)
		in.DeadlineMS = time.Now().Add(5 * time.Second).UnixMilli()
		if expired {
			in.DeadlineMS = time.Now().Add(-time.Second).UnixMilli()
		}
		op.Input, _ = json.Marshal(in)
		w := invokeFailover(m, op, context.Background())
		if expired {
			if w.Code != 408 || len(g.calls) != 0 {
				t.Fatal(w.Code, w.Body.String())
			}
			continue
		}
		if w.Code != 200 || len(g.calls) != 1 {
			t.Fatal(w.Code, w.Body.String())
		}
		state, _, err := m.modelStore.(ModelRouteExecutionStore).LookupModelRouteExecution(context.Background(), modelSelectionScopeHash(scopeFromHarness(op.Context)), "logical-call")
		if err != nil || state.Deadline.UnixMilli() != in.DeadlineMS {
			t.Fatal("original deadline not durable", state.Deadline, err)
		}
		in.DeadlineMS += 30000
		op.Input, _ = json.Marshal(in)
		w = invokeFailover(m, op, context.Background())
		if w.Code != 409 || len(g.calls) != 1 {
			t.Fatal("resume changed original deadline or resent", w.Code, w.Body.String())
		}
	}
}

func TestRouteExecutionUnknownOutcomeContinuesOnceAndPinsResult(t *testing.T) {
	m, op, g, b := resilientInvocationFixture(t)
	g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
	w := invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || len(b.released) != 0 || len(b.settled) != 1 || !strings.Contains(w.Body.String(), `"retained_unknown_attempts":1`) {
		t.Fatal("unknown primary must retain its exposure and use a fresh alternate", w.Code, w.Body.String(), len(g.calls), len(b.released), len(b.settled))
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	state, found, err := store.LookupModelRouteExecution(context.Background(), scope, "logical-call")
	if err != nil || !found || state.Status != "completed" || len(state.Steps) != 2 || state.Steps[0].Disposition != "retained_unknown" {
		t.Fatal(state, err)
	}
	before := modelRouteHash(state)
	if err := m.CheckTaskModelQuiescence(context.Background(), scopeFromHarness(op.Context)); err != nil {
		t.Fatal("disposed unknown still blocks business completion", err)
	}
	// A late physical completion is accounting-only. This is deliberate fixture
	// corruption of the original body to prove replay never chooses it again.
	store.mu.Lock()
	key := scope + "\x00logical-call"
	original := store.records[key]
	original.Status, original.Response = "completed", map[string]any{"text": "late original must not win"}
	store.records[key] = original
	store.mu.Unlock()
	w = invokeFailover(m, op, context.Background())
	if w.Code != 200 || len(g.calls) != 2 || strings.Contains(w.Body.String(), "late original") || len(b.settled) != 1 {
		t.Fatal("late result replaced winner or replay sent again", w.Code, w.Body.String())
	}
	state, _, _ = store.LookupModelRouteExecution(context.Background(), scope, "logical-call")
	if modelRouteHash(state) != before {
		t.Fatal("frozen execution changed")
	}
	w = httptest.NewRecorder()
	m.modelReceiptAuthorized(w, httptest.NewRequest("POST", "/internal/model/generate/receipt", nil), op, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"completed"`) || strings.Contains(w.Body.String(), "late original") {
		t.Fatal(w.Code, w.Body.String())
	}
	var in modelGenerateInput
	_ = json.Unmarshal(op.Input, &in)
	in.Messages = routeRequest("different input").Messages
	op.Input, _ = json.Marshal(in)
	w = invokeFailover(m, op, context.Background())
	if w.Code != 409 || len(g.calls) != 2 {
		t.Fatal("changed input reused a logical operation", w.Code, w.Body.String())
	}
}

func TestRouteExecutionCancellationAndLegacyPolicy(t *testing.T) {
	for _, kind := range []string{"cancel", "legacy", "no-opt-in"} {
		t.Run(kind, func(t *testing.T) {
			m, op, g, b := resilientInvocationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel" {
				g.cancel = cancel
			}
			if kind == "legacy" {
				op.Policy.Model.Routing.Availability.Version = "model-route-availability/v1"
				op.Policy.Model.Routing.Availability.UnknownOutcome = ""
				op.Policy.Model.Routing.Availability.AttemptTimeoutSeconds = 0
			}
			if kind == "no-opt-in" {
				op.Policy.Model.Routing.Availability.UnknownOutcome = ""
			}
			g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
			w := invokeFailover(m, op, ctx)
			if w.Code == 200 || len(g.calls) != 1 || len(b.released) != 0 || len(b.settled) != 0 {
				t.Fatal("unapproved/cancelled continuation", w.Code, w.Body.String(), len(g.calls))
			}
		})
	}
}

type holdFailureBudget struct{ captureModelBudgetStore }

func (*holdFailureBudget) MarkReconciliationNeeded(context.Context, usagecost.ModelBudgetReservation) error {
	return errors.New("fixture hold persistence unavailable")
}

func TestRouteExecutionMissingHoldAndExpiredDeadlineCannotAdvance(t *testing.T) {
	for _, mode := range []string{"hold-failed", "expired", "unknown-not-disposed"} {
		t.Run(mode, func(t *testing.T) {
			m, op, g, _ := resilientInvocationFixture(t)
			g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
			store := m.modelStore.(*memoryModelInvocationStore)
			scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
			if mode == "hold-failed" {
				m.modelBudgets = &holdFailureBudget{}
			}
			if mode == "expired" {
				var in modelGenerateInput
				_ = json.Unmarshal(op.Input, &in)
				check := op
				route, _, err := m.resolveInvocationRoute(context.Background(), &check, "logical-call", routeInput(in), 0, "", nil, false)
				if err != nil {
					t.Fatal(err)
				}
				_, err = store.BeginModelRouteExecution(context.Background(), scope, "logical-call", ModelRouteExecution{Version: "model-route-execution/v1", RequestFingerprint: route.RequestFingerprint, PolicySHA256: route.Decision.PolicySHA256, MaxAttempts: 3, Revision: 1, Status: "active", Deadline: time.Now().Add(-time.Second)})
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unknown-not-disposed" {
				op.Policy.Model.Routing.Availability.UnknownOutcome = ""
			}
			w := invokeFailover(m, op, context.Background())
			if w.Code == 200 || len(g.calls) > 1 || mode == "expired" && len(g.calls) != 0 {
				t.Fatal(w.Code, w.Body.String(), len(g.calls))
			}
			if mode != "expired" && m.CheckTaskModelQuiescence(context.Background(), scopeFromHarness(op.Context)) == nil {
				t.Fatal("unproven hold or undisposed call became quiescent")
			}
		})
	}
}

func TestRouteExecutionManualOptInUsesPublishedPrimary(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		m, op, g, _ := resilientInvocationFixture(t)
		store := m.modelStore.(*memoryModelInvocationStore)
		scope := scopeFromHarness(op.Context)
		scope.RunID = "manual-root"
		op.Context.TaskID = scope.RunID
		op.Policy.Model.Routing.Availability.ManualFallback = enabled
		if err := store.BindModelSelection(context.Background(), scope, policyasset.ModelSelectionBinding{Selection: policyasset.ModelSelection{Mode: "manual"}, PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
			t.Fatal(err)
		}
		g.firstError = &modelgateway.ProviderFailure{Category: "body_read"}
		w := invokeFailover(m, op, context.Background())
		if enabled {
			if w.Code != 200 || len(g.calls) != 2 || g.calls[0].ModelVersionID != op.Policy.Model.ModelVersionID || g.calls[1].ModelVersionID == g.calls[0].ModelVersionID {
				t.Fatal("manual fallback must start with published primary", w.Code, w.Body.String(), g.calls)
			}
		} else if w.Code == 200 || len(g.calls) != 1 {
			t.Fatal("legacy manual must retain fixed selection", w.Code, w.Body.String())
		}
	}
}
