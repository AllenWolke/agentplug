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

type routeCatalogFixture struct {
	models     map[string]modelgateway.RoutingMetadata
	denied     map[string]error
	prices     map[string]modelgovernance.PriceVersion
	priceErr   error
	priceCalls int
}

func (f *routeCatalogFixture) ResolveRoutingModel(_ context.Context, _ sharedkernel.Scope, id string) (modelgateway.RoutingMetadata, error) {
	if err := f.denied[id]; err != nil {
		return modelgateway.RoutingMetadata{}, err
	}
	return f.models[id], nil
}
func (f *routeCatalogFixture) ResolvePrice(_ context.Context, id string, _ time.Time) (modelgovernance.PriceVersion, error) {
	f.priceCalls++
	return f.prices[id], f.priceErr
}

func routeFixture() (sharedkernel.Scope, policyasset.ModelRoutingPolicy, *routeCatalogFixture, time.Time) {
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "dept", ApplicationID: "app", AgentInstanceID: "instance",
		AgentID: "agent", PrincipalID: "actor", PrincipalType: "user", InstallationID: "installation", AgentVersionID: "agent-v1", SessionID: "session", RunID: "root", AuthorizationEpoch: 1, TraceID: "trace"}
	p := policyasset.ModelRoutingPolicy{Version: "model-routing/v1", ExecutionContextSHA256: strings.Repeat("c", 64), SimpleMaxInputTokens: 256, ComplexMinInputTokens: 1024, SimpleMaxOutputTokens: 128, MaxEstimatedMicros: 100000}
	f := &routeCatalogFixture{models: map[string]modelgateway.RoutingMetadata{}, prices: map[string]modelgovernance.PriceVersion{}, denied: map[string]error{}}
	at := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	for i, id := range []string{"small", "medium", "large"} {
		trust, rate := "local", int64(0)
		if id == "large" {
			trust, rate = "external", 300
		}
		m := modelgateway.RoutingMetadata{Selection: modelgateway.Selection{ModelVersionID: id, ProviderID: "provider-" + id, ProviderKey: "provider-" + id, ModelID: "model-" + id, ModelKey: id, TrustZone: trust, DeploymentID: "deployment-" + id, EndpointRef: "service://local", CapacityUnits: 1}, Kind: "chat", ContextLimit: 8192, SupportsFunctions: id == "large", SupportsJSON: true}
		f.models[id] = m
		f.prices[id] = modelgovernance.PriceVersion{ID: "price-" + id, ModelVersionID: id, Currency: "USD", InputMicrosPer1K: rate, OutputMicrosPer1K: rate * 4, EffectiveFrom: at.Add(-time.Hour), ContentHash: "sha256:" + strings.Repeat("a", 64), Status: "approved", Revision: 2}
		p.Candidates = append(p.Candidates, policyasset.ModelRouteCandidate{ModelVersionID: id, PriceVersionID: "price-" + id, QualityEvidenceID: "evidence-" + id, CapabilitySHA256: m.CapabilitySHA256(), QualityEvidenceSHA256: strings.Repeat("b", 64), MaxComplexity: []string{"simple", "medium", "complex"}[i]})
	}
	return scope, p, f, at
}

func routeRequest(text string) ModelRouteRequest {
	return ModelRouteRequest{Messages: []modelgateway.Message{{Role: "system", Content: "answer grounded in evidence"}, {Role: "user", Content: text}}, MaxTokens: 64}
}

func TestMixedLocalAPIPrefixPoolRequiresExplicitPreparationFallback(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		scope, p, f, at := routeFixture()
		large := f.models["large"]
		large.ContextCacheMode = "provider_prefix"
		f.models["large"] = large
		p.Candidates[2].CapabilitySHA256 = large.CapabilitySHA256()
		request := routeRequest("解释指标定义")
		request.ContextCacheMode = "provider_prefix"
		request.AllowUnreportedPrefixPreparation = fallback
		d, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, f, f, at)
		want := "large"
		if fallback {
			want = "small"
		}
		if err != nil || d.ModelVersionID != want {
			t.Fatal("mixed capability selection", fallback, d.ModelVersionID, err)
		}
	}
}

func TestModelRouteComplexityAndCost(t *testing.T) {
	for _, test := range []struct {
		name, text       string
		tokens           int
		want, complexity string
	}{
		{"known simple", "解释指标定义", 64, "small", "simple"},
		{"larger answer", "解释指标定义", 256, "medium", "medium"},
		{"multi-date", "2026-06-30和2026-07-31的定义是什么", 64, "large", "complex"},
		{"comparison", "对比两份政策的指标定义", 64, "large", "complex"},
		{"unknown short", "zcq987", 64, "large", "complex"},
		{"long input", "定义" + strings.Repeat("x", 1100), 64, "large", "complex"},
		{"middle input", "定义" + strings.Repeat("x", 300), 64, "medium", "medium"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, p, f, at := routeFixture()
			request := routeRequest(test.text)
			request.MaxTokens = test.tokens
			d, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, f, f, at)
			if err != nil || d.ModelVersionID != test.want || d.Features.Complexity != test.complexity {
				t.Fatalf("unexpected selection %s/%s: %v", d.ModelVersionID, d.Features.Complexity, err)
			}
			if len(d.PolicySHA256) != 64 || len(d.FeaturesSHA256) != 64 || d.Price.ID != "price-"+test.want {
				t.Fatal("missing frozen decision bindings")
			}
			if test.want == "small" && d.EstimatedMicros != 0 {
				t.Fatal("local tariff must remain distinct from infrastructure cost")
			}
		})
	}
}

func TestModelRouteFiltersBeforeChoosing(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*policyasset.ModelRoutingPolicy, *routeCatalogFixture)
		allow  bool
		want   string
	}{
		{"permission revoked", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			f.denied["small"] = modelgovernance.ErrModelAccessDenied
		}, true, "medium"},
		{"disabled catalog", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			f.denied["small"] = modelgovernance.ErrNotFound
		}, true, "medium"},
		{"changed capabilities", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			m := f.models["small"]
			m.ContextLimit = 4096
			f.models["small"] = m
		}, true, "medium"},
		{"local deployment missing", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			m := f.models["small"]
			m.Selection.DeploymentID = ""
			f.models["small"] = m
		}, true, "medium"},
		{"price replaced", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			m := f.prices["small"]
			m.ID = "new-price"
			f.prices["small"] = m
		}, true, "medium"},
		{"expired price", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			m := f.prices["small"]
			end := m.EffectiveFrom.Add(time.Minute)
			m.EffectiveUntil = &end
			f.prices["small"] = m
		}, true, "medium"},
		{"external blocked", func(_ *policyasset.ModelRoutingPolicy, f *routeCatalogFixture) {
			f.denied["small"] = modelgovernance.ErrModelAccessDenied
			f.denied["medium"] = modelgovernance.ErrModelAccessDenied
		}, false, ""},
		{"unverified quality tier", func(p *policyasset.ModelRoutingPolicy, _ *routeCatalogFixture) {
			p.Candidates[0].QualityEvidenceSHA256 = ""
		}, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, p, f, at := routeFixture()
			test.mutate(&p, f)
			d, err := SelectModelRoute(context.Background(), scope, p, routeRequest("解释定义"), policyasset.ToolPolicy{}, test.allow, f, f, at)
			if test.want == "" {
				if err == nil {
					t.Fatal("invalid route admitted")
				}
				return
			}
			if err != nil || d.ModelVersionID != test.want {
				t.Fatalf("selection %s: %v", d.ModelVersionID, err)
			}
			if len(d.Excluded) == 0 {
				t.Fatal("missing exclusion reason")
			}
		})
	}
}

func TestModelRouteFailClosedAndCancellation(t *testing.T) {
	scope, p, f, at := routeFixture()
	f.denied["small"] = errors.New("authorization store unavailable")
	if _, err := SelectModelRoute(context.Background(), scope, p, routeRequest("定义是什么"), policyasset.ToolPolicy{}, true, f, f, at); !errors.Is(err, ErrModelRouteUnavailable) {
		t.Fatal("authorization outage must not silently reroute")
	}
	if f.priceCalls != 0 {
		t.Fatal("unauthorized model priced")
	}
	scope, p, f, at = routeFixture()
	f.priceErr = errors.New("price store unavailable")
	if _, err := SelectModelRoute(context.Background(), scope, p, routeRequest("定义是什么"), policyasset.ToolPolicy{}, true, f, f, at); !errors.Is(err, ErrModelRouteUnavailable) {
		t.Fatal("pricing outage admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SelectModelRoute(ctx, scope, p, routeRequest("定义是什么"), policyasset.ToolPolicy{}, true, f, f, at); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled selection admitted")
	}
}

func TestModelRouteBudgetContextAndJSON(t *testing.T) {
	for _, name := range []string{"budget", "context", "json", "scope"} {
		t.Run(name, func(t *testing.T) {
			scope, p, f, at := routeFixture()
			request := routeRequest("对比指标定义")
			switch name {
			case "budget":
				p.MaxEstimatedMicros = 1
			case "context":
				m := f.models["large"]
				m.ContextLimit = 10
				f.models["large"] = m
				p.Candidates[2].CapabilitySHA256 = m.CapabilitySHA256()
			case "json":
				request.RequireJSON = true
				m := f.models["large"]
				m.SupportsJSON = false
				f.models["large"] = m
				p.Candidates[2].CapabilitySHA256 = m.CapabilitySHA256()
			case "scope":
				scope.AuthorizationEpoch = 0
			}
			if _, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, f, f, at); err == nil {
				t.Fatal("unsatisfied route constraint admitted")
			}
		})
	}
}

func TestModelRouteToolTranscriptAndSchema(t *testing.T) {
	scope, p, f, at := routeFixture()
	request := routeRequest("指标定义是什么")
	request.FunctionNames = []string{"unpublished"}
	if _, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, f, f, at); err == nil {
		t.Fatal("unpublished tool admitted by routing")
	}
	request.FunctionNames = nil
	request.Messages = append(request.Messages, modelgateway.Message{Role: "user", Content: "补充定义"})
	d, err := SelectModelRoute(context.Background(), scope, p, request, policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil || d.ModelVersionID != "large" {
		t.Fatal("multi-turn routed down")
	}
}

// Drafted after the user requested developing all features before the next
// test phase. These scenarios are not evidence of another real API provider.
func TestModelRouteAcrossAPIProviders(t *testing.T) {
	scope, p, f, at := routeFixture()
	for index, id := range []string{"small", "medium"} {
		m := f.models[id]
		m.Selection.TrustZone, m.Selection.ProviderKey = "external", "independent-cloud-"+id
		m.Selection.DeploymentID, m.Selection.EndpointRef, m.Selection.CapacityUnits = "", "", 0
		f.models[id] = m
		p.Candidates[index].CapabilitySHA256 = m.CapabilitySHA256()
		price := f.prices[id]
		price.InputMicrosPer1K, price.OutputMicrosPer1K = int64(10+index*20), int64(40+index*80)
		f.prices[id] = price
	}
	decision, err := SelectModelRoute(context.Background(), scope, p, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil || decision.ModelVersionID != "small" || decision.EstimatedMicros <= 0 {
		t.Fatal("non-DeepSeek API model was not priced and selected")
	}
	f.denied["small"] = modelgovernance.ErrModelAccessDenied
	decision, err = SelectModelRoute(context.Background(), scope, p, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil || decision.ModelVersionID != "medium" {
		t.Fatal("alternate approved API provider was not selected")
	}
	decision, err = SelectModelRoute(context.Background(), scope, p, routeRequest("跨版本对比指标定义"), policyasset.ToolPolicy{}, true, f, f, at)
	if err != nil || decision.ModelVersionID != "large" {
		t.Fatal("complex task crossed the API candidate quality boundary")
	}
	if _, err = SelectModelRoute(context.Background(), scope, p, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, false, f, f, at); !errors.Is(err, ErrModelRouteNoCandidate) {
		t.Fatal("external API model escaped allow_external=false")
	}
}
