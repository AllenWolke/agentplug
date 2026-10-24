package capability

import (
	"context"
	"log"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func modelAvailabilityPartition(scope sharedkernel.Scope) string {
	return modelRouteHash(struct{ Tenant, Department, Application string }{scope.TenantID, scope.DepartmentID, scope.ApplicationID})
}

type availableRoutingMetadata struct {
	modelgateway.RoutingMetadataResolver
	store ModelRouteAvailabilityStore
	at    time.Time
}

func (r availableRoutingMetadata) ResolveRoutingModel(ctx context.Context, scope sharedkernel.Scope, model string) (modelgateway.RoutingMetadata, error) {
	// Current approval and IAM are always checked; health never grants access.
	metadata, err := r.RoutingMetadataResolver.ResolveRoutingModel(ctx, scope, model)
	if err != nil {
		return metadata, err
	}
	s, found, err := r.store.LookupModelAvailability(ctx, modelAvailabilityPartition(scope), model)
	if err != nil {
		return modelgateway.RoutingMetadata{}, ErrModelRouteUnavailable
	}
	if found && (!s.OpenUntil.IsZero() && r.at.Before(s.OpenUntil) || s.ProbeOwner != "" && r.at.Before(s.ProbeUntil)) {
		return modelgateway.RoutingMetadata{}, ErrModelRouteCandidateUnavailable
	}
	return metadata, nil
}

// claimModelAvailability permits only one fresh request to probe after cooldown.
// Existing route decisions stay immutable; this lease does not authorize retries.
func claimModelAvailability(ctx context.Context, store ModelRouteAvailabilityStore, partition, model, owner string,
	p policyasset.ModelRouteAvailabilityPolicy, at time.Time) error {
	if store == nil || p.Validate() != nil || !isRouteSHA(owner) || at.IsZero() {
		return ErrModelRouteUnavailable
	}
	for n := 0; n < 4; n++ {
		s, found, err := store.LookupModelAvailability(ctx, partition, model)
		if err != nil {
			return err
		}
		if !found || s.OpenUntil.IsZero() {
			return nil
		}
		if s.ProbeOwner == owner && at.Before(s.ProbeUntil) {
			return nil
		}
		if at.Before(s.OpenUntil) || s.ProbeOwner != "" && at.Before(s.ProbeUntil) {
			return ErrModelRouteCandidateUnavailable
		}
		revision := s.Revision
		s.Revision++
		s.ProbeOwner, s.ProbeUntil = owner, at.Add(time.Duration(p.ProbeSeconds)*time.Second)
		ok, err := store.CompareAndSwapModelAvailability(ctx, partition, model, revision, s)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrModelRouteUnavailable
}

func recordModelAvailability(ctx context.Context, store ModelRouteAvailabilityStore, partition, model, owner string,
	p policyasset.ModelRouteAvailabilityPolicy, started, finished time.Time, succeeded bool) error {
	if store == nil || p.Validate() != nil || !isRouteSHA(owner) || started.IsZero() || finished.Before(started) {
		return ErrModelRouteUnavailable
	}
	for n := 0; n < 4; n++ {
		s, _, err := store.LookupModelAvailability(ctx, partition, model)
		if err != nil {
			return err
		}
		// Duplicates and late outcomes from before a circuit opened cannot reset
		// the cooldown or overwrite a newer probe's result.
		if s.LastAttempt == owner || started.Before(s.LastStartedAt) ||
			!s.OpenUntil.IsZero() && s.ProbeOwner != owner {
			return nil
		}
		revision := s.Revision
		s.Revision++
		s.LastAttempt, s.LastStartedAt, s.LastFinishedAt = owner, started, finished
		s.ProbeOwner, s.ProbeUntil = "", time.Time{}
		if succeeded {
			s.Failures, s.OpenUntil = 0, time.Time{}
		} else {
			if s.Failures < 10 {
				s.Failures++
			}
			if s.Failures >= p.FailureThreshold {
				s.OpenUntil = finished.Add(time.Duration(p.CooldownSeconds) * time.Second)
			}
		}
		ok, err := store.CompareAndSwapModelAvailability(ctx, partition, model, revision, s)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrModelRouteUnavailable
}

func affectsModelAvailability(err error) bool {
	if err == nil {
		return true
	}
	kind := modelProviderErrorKind(err)
	switch kind {
	case "provider_unavailable", "model_unavailable", "endpoint_unresolved", "secret_unavailable", "invalid_response", "response_too_large",
		"provider_dial_timeout", "provider_tls_timeout", "provider_response_timeout", "provider_transport_timeout", "provider_network", "provider_body_read",
		"provider_http_401", "provider_http_403", "provider_http_408", "provider_http_429", "provider_http_500", "provider_http_502", "provider_http_503", "provider_http_504":
		return true
	}
	return false
}

func (m *Module) recordRouteAvailability(ctx context.Context, route *StoredModelRoute, op envelope, key, token string, started, finished time.Time, err error) {
	if route == nil || op.Policy.Model.Routing == nil || op.Policy.Model.Routing.Availability == nil || !affectsModelAvailability(err) {
		return
	}
	store, ok := m.modelStore.(ModelRouteAvailabilityStore)
	if !ok {
		return
	}
	writeCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer stop()
	owner := modelRouteHash(struct{ Scope, Key, Token string }{modelSelectionScopeHash(scopeFromHarness(op.Context)), key, token})
	if writeErr := recordModelAvailability(writeCtx, store, modelAvailabilityPartition(scopeFromHarness(op.Context)), route.Decision.ModelVersionID,
		owner, *op.Policy.Model.Routing.Availability, started, finished, err == nil); writeErr != nil {
		// Never lose a valid billable response or resend because health storage failed.
		log.Printf("model route availability observation deferred trace=%q error_type=%T", op.Context.TraceID, writeErr)
	}
}
