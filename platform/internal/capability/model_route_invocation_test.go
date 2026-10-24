package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (f *routeCatalogFixture) ResolveModel(ctx context.Context, scope sharedkernel.Scope, id string) (modelgateway.Selection, error) {
	m, err := f.ResolveRoutingModel(ctx, scope, id)
	return m.Selection, err
}

type routeNoSendGateway struct{ calls int }

func (g *routeNoSendGateway) Generate(context.Context, sharedkernel.Scope, policyasset.Snapshot, modelgateway.GenerateRequest) (modelgateway.GenerateResult, error) {
	g.calls++
	return modelgateway.GenerateResult{}, errors.New("unexpected provider call")
}
func (g *routeNoSendGateway) Embed(context.Context, sharedkernel.Scope, policyasset.Snapshot, []string) ([][]float32, error) {
	g.calls++
	return nil, errors.New("unexpected provider call")
}

func routeInvocationFixture(t *testing.T) (*Module, envelope, *routeCatalogFixture, *routeNoSendGateway) {
	t.Helper()
	s, p, catalog, _ := routeFixture()
	for id, price := range catalog.prices {
		price.EffectiveFrom = time.Now().UTC().Add(-time.Hour)
		catalog.prices[id] = price
	}
	op := envelope{Context: harnessContext{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID,
		AgentID: s.AgentID, AgentVersionID: s.AgentVersionID, AgentInstanceID: s.AgentInstanceID, ActorID: s.PrincipalID,
		PrincipalType: s.PrincipalType, InstallationID: s.InstallationID, SessionID: s.SessionID, TaskID: s.RunID,
		AuthorizationEpoch: s.AuthorizationEpoch, TraceID: s.TraceID}, Policy: policyasset.Snapshot{Hash: strings.Repeat("c", 64),
		Model: policyasset.ModelPolicy{Provider: "provider-large", Model: "large", ModelVersionID: "large", MaxTokens: 256, AllowExternal: true, Routing: &p}}}
	p.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(op.Policy)
	store := newMemoryModelInvocationStore()
	if err := store.BindModelSelection(context.Background(), scopeFromHarness(op.Context), policyasset.ModelSelectionBinding{
		Selection: policyasset.ModelSelection{Mode: "automatic"}, PolicySHA256: op.Policy.Hash, CommandFingerprint: strings.Repeat("d", 64)}); err != nil {
		t.Fatal(err)
	}
	gateway := &routeNoSendGateway{}
	return &Module{modelStore: store, modelAccess: catalog, modelGateway: gateway, modelPrices: catalog}, op, catalog, gateway
}

func TestRouteReceiptLookupDoesNotSelectPersistOrSend(t *testing.T) {
	m, op, catalog, gateway := routeInvocationFixture(t)
	route, automatic, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("指标定义是什么"), 0, "prompt", nil, true)
	if err != nil || !automatic || route != nil || catalog.priceCalls != 0 || gateway.calls != 0 {
		t.Fatal("receipt lookup performed admission or selection")
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	if len(store.routes) != 0 || len(store.records) != 0 {
		t.Fatal("receipt read created durable calls")
	}
}

func TestInvocationRouteKeepsOriginalChoiceAndRejectsChangedRequest(t *testing.T) {
	m, original, catalog, gateway := routeInvocationFixture(t)
	op := original
	route, automatic, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("指标定义是什么"), 0, "prompt", nil, false)
	if err != nil || !automatic || route == nil || op.Policy.Model.ModelVersionID != "small" {
		t.Fatal("route not pinned", err)
	}
	calls := catalog.priceCalls
	// An unrelated candidate outage and changing prices cannot reroute an existing receipt.
	catalog.denied["large"] = errors.New("unrelated catalog outage")
	delete(catalog.prices, "small")
	op = original
	replayed, _, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("指标定义是什么"), 0, "prompt", nil, true)
	if err != nil || replayed == nil || replayed.DecisionSHA256 != route.DecisionSHA256 || catalog.priceCalls != calls || gateway.calls != 0 {
		t.Fatal("replay reselected or sent")
	}
	op = original
	if _, _, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("比较多个版本"), 0, "prompt", nil, false); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("changed intent accepted")
	}
	catalog.denied["small"] = modelgovernance.ErrModelAccessDenied
	op = original
	if _, _, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("指标定义是什么"), 0, "prompt", nil, true); !errors.Is(err, modelgovernance.ErrModelAccessDenied) {
		t.Fatal("revoked selected model replayed")
	}
}

func TestModelSelectionPinsScopePolicyAndIntent(t *testing.T) {
	m, op, _, _ := routeInvocationFixture(t)
	store := m.modelStore.(policyasset.ModelSelectionStore)
	scope := scopeFromHarness(op.Context)
	b, found, err := store.LookupModelSelection(context.Background(), scope)
	if err != nil || !found {
		t.Fatal("binding absent")
	}
	changed := b
	changed.Selection.Mode = "manual"
	if !errors.Is(store.BindModelSelection(context.Background(), scope, changed), ErrModelInvocationConflict) {
		t.Fatal("mode changed after acceptance")
	}
	scope.RunID = "another-root"
	if _, found, err := store.LookupModelSelection(context.Background(), scope); err != nil || found {
		t.Fatal("Run preference crossed root boundary")
	}
}

func TestRouteSummaryUnknownCostIsNotZero(t *testing.T) {
	m, op, _, _ := routeInvocationFixture(t)
	route, _, err := m.resolveInvocationRoute(context.Background(), &op, "request", routeRequest("指标定义是什么"), 0, "prompt", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := routeSummaryReceipt(*route, ModelInvocation{Status: "reconcile"}, true)
	if err != nil || summary.ActualCostMicros != nil {
		t.Fatal("unknown billing replaced by zero")
	}
	_, err = routeSummaryReceipt(*route, ModelInvocation{Status: "completed", Response: map[string]any{}}, true)
	if !errors.Is(err, ErrModelRouteUnavailable) {
		t.Fatal("missing finalized billing accepted")
	}
}
