package capability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

func availabilityPolicy() policyasset.ModelRouteAvailabilityPolicy {
	return policyasset.ModelRouteAvailabilityPolicy{Version: "model-route-availability/v1", FailureThreshold: 1, CooldownSeconds: 30, ProbeSeconds: 10, MaxAttempts: 3}
}

func TestRouteAvailabilityExcludesOnlyFailedCandidates(t *testing.T) {
	scope, policy, catalog, at := routeFixture()
	store := newMemoryModelInvocationStore()
	partition := modelAvailabilityPartition(scope)
	if err := recordModelAvailability(context.Background(), store, partition, "small", strings.Repeat("a", 64), availabilityPolicy(), at, at.Add(time.Second), false); err != nil {
		t.Fatal(err)
	}
	resolver := availableRoutingMetadata{RoutingMetadataResolver: catalog, store: store, at: at.Add(2 * time.Second)}
	d, err := SelectModelRoute(context.Background(), scope, policy, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, resolver, catalog, at)
	if err != nil || d.ModelVersionID != "medium" || len(d.Excluded) == 0 || d.Excluded[0].Reason != "temporarily_unavailable" {
		t.Fatal("unhealthy candidate prevented a compatible route", d, err)
	}
	// Another application cannot inherit the health row or its diagnostic.
	scope.ApplicationID = "other-application"
	d, err = SelectModelRoute(context.Background(), scope, policy, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, resolver, catalog, at)
	if err != nil || d.ModelVersionID != "small" {
		t.Fatal("availability crossed application boundary", err)
	}
	// A real catalog/authorization dependency failure still fails closed.
	catalog.denied["small"] = errors.New("database unavailable")
	if _, err := SelectModelRoute(context.Background(), scope, policy, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, resolver, catalog, at); !errors.Is(err, ErrModelRouteUnavailable) {
		t.Fatal("dependency failure hidden", err)
	}
}

func TestRouteLocalUnavailableDoesNotAbortOtherModels(t *testing.T) {
	scope, policy, catalog, at := routeFixture()
	catalog.denied["small"] = modelcapacity.ErrUnavailable
	d, err := SelectModelRoute(context.Background(), scope, policy, routeRequest("指标定义是什么"), policyasset.ToolPolicy{}, true, catalog, catalog, at)
	if err != nil || d.ModelVersionID != "medium" {
		t.Fatal("local outage aborted pool", err)
	}
	catalog.denied["large"] = modelcapacity.ErrUnavailable
	if _, err := SelectModelRoute(context.Background(), scope, policy, routeRequest("比较多个制度"), policyasset.ToolPolicy{}, true, catalog, catalog, at); !errors.Is(err, ErrModelRouteNoCandidate) {
		t.Fatal("complex task downgraded after outage", err)
	}
}

func TestRouteAvailabilityProbeCASAndStaleOutcome(t *testing.T) {
	ctx := context.Background()
	store := newMemoryModelInvocationStore()
	scope, _, _, at := routeFixture()
	partition, p := modelAvailabilityPartition(scope), availabilityPolicy()
	first := strings.Repeat("a", 64)
	if err := recordModelAvailability(ctx, store, partition, "large", first, p, at, at.Add(time.Second), false); err != nil {
		t.Fatal(err)
	}
	if err := claimModelAvailability(ctx, store, partition, "large", strings.Repeat("b", 64), p, at.Add(2*time.Second)); !errors.Is(err, ErrModelRouteCandidateUnavailable) {
		t.Fatal("cooldown bypassed", err)
	}
	var wg sync.WaitGroup
	winners := make(chan string, 8)
	for i := 0; i < 8; i++ {
		owner := modelRouteHash(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := claimModelAvailability(ctx, store, partition, "large", owner, p, at.Add(32*time.Second))
			if err == nil {
				winners <- owner
			} else if !errors.Is(err, ErrModelRouteCandidateUnavailable) && !errors.Is(err, ErrModelRouteUnavailable) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(winners)
	var winner string
	n := 0
	for owner := range winners {
		winner = owner
		n++
	}
	if n != 1 {
		t.Fatal("expected one recovery probe", n)
	}
	// A result from the pre-outage call cannot close the circuit.
	if err := recordModelAvailability(ctx, store, partition, "large", first, p, at, at.Add(33*time.Second), true); err != nil {
		t.Fatal(err)
	}
	state, _, _ := store.LookupModelAvailability(ctx, partition, "large")
	if state.ProbeOwner != winner || state.OpenUntil.IsZero() {
		t.Fatal("stale result replaced probe")
	}
	newOwner := strings.Repeat("e", 64)
	if err := claimModelAvailability(ctx, store, partition, "large", newOwner, p, at.Add(43*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := recordModelAvailability(ctx, store, partition, "large", winner, p, at.Add(32*time.Second), at.Add(44*time.Second), true); err != nil {
		t.Fatal(err)
	}
	state, _, _ = store.LookupModelAvailability(ctx, partition, "large")
	if state.ProbeOwner != newOwner {
		t.Fatal("expired probe overwrote new owner")
	}
	if err := recordModelAvailability(ctx, store, partition, "large", newOwner, p, at.Add(43*time.Second), at.Add(45*time.Second), true); err != nil {
		t.Fatal(err)
	}
	state, _, _ = store.LookupModelAvailability(ctx, partition, "large")
	if !state.OpenUntil.IsZero() || state.Failures != 0 || state.ProbeOwner != "" {
		t.Fatal("probe did not restore model")
	}
}

func TestRouteAvailabilityClassifiesOnlyProviderFailures(t *testing.T) {
	for _, err := range []error{modelgateway.ErrSecretUnavailable, modelgateway.ErrProviderResponse, &modelgateway.ProviderFailure{Category: "body_read"}, &modelgateway.ProviderFailure{Category: "http_response", StatusCode: 503}} {
		if !affectsModelAvailability(err) {
			t.Fatal("provider failure ignored", err)
		}
	}
	for _, err := range []error{context.Canceled, modelgateway.ErrRequestTooLarge, &modelgateway.ProviderFailure{Category: "cancelled"}, &modelgateway.ProviderFailure{Category: "http_response", StatusCode: 400}} {
		if affectsModelAvailability(err) {
			t.Fatal("request error poisoned shared availability", err)
		}
	}
}

func TestRouteAvailabilityPolicyBounds(t *testing.T) {
	for _, mutate := range []func(*policyasset.ModelRouteAvailabilityPolicy){
		func(p *policyasset.ModelRouteAvailabilityPolicy) { p.Version = "other" },
		func(p *policyasset.ModelRouteAvailabilityPolicy) { p.FailureThreshold = 0 },
		func(p *policyasset.ModelRouteAvailabilityPolicy) { p.CooldownSeconds = 301 },
		func(p *policyasset.ModelRouteAvailabilityPolicy) { p.ProbeSeconds = 61 },
		func(p *policyasset.ModelRouteAvailabilityPolicy) { p.MaxAttempts = 4 },
	} {
		p := availabilityPolicy()
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("unbounded availability policy accepted")
		}
	}
}
