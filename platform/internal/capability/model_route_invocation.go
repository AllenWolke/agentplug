package capability

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
)

// resolveInvocationRoute is shared by generation and read-only receipt lookup.
// A lookup never creates a decision or calls a provider. A send always uses the
// persisted winner and the existing governed admission/recovery pipeline.
func (m *Module) resolveInvocationRoute(ctx context.Context, op *envelope, key string,
	request ModelRouteRequest, temperature float64, promptHash string,
	skills map[string]SkillModelBinding, lookupOnly bool) (*StoredModelRoute, bool, error) {
	if op.Policy.Model.Routing == nil {
		return nil, false, nil
	}
	if op.Policy.Model.ValidateRouting() != nil || op.Policy.Model.Routing.ExecutionContextSHA256 != policyasset.RoutingExecutionContextSHA256(op.Policy) {
		return nil, false, policyasset.ErrMissingPolicy
	}
	selections, ok := m.modelStore.(policyasset.ModelSelectionStore)
	if !ok {
		return nil, false, ErrModelRouteUnavailable
	}
	scope := scopeFromHarness(op.Context)
	binding, found, err := selections.LookupModelSelection(ctx, scope)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	} // Existing/machine Runs keep fixed selection.
	if binding.PolicySHA256 != op.Policy.Hash {
		return nil, false, ErrModelInvocationConflict
	}
	manualFallback := op.Policy.Model.Routing.Availability != nil && op.Policy.Model.Routing.Availability.Version == "model-route-availability/v2" && op.Policy.Model.Routing.Availability.ManualFallback
	if binding.Selection.EffectiveMode() != "automatic" && !manualFallback {
		return nil, false, nil
	}
	store, ok := m.modelStore.(ModelRouteDecisionStore)
	metadata, metadataOK := m.modelAccess.(modelgateway.RoutingMetadataResolver)
	if !ok || !metadataOK || m.modelGateway == nil || m.modelPrices == nil {
		return nil, true, ErrModelRouteUnavailable
	}
	p := *op.Policy.Model.Routing
	fallback, _ := ctx.Value(modelRouteFallbackKey{}).(routeFallbackContext)
	if binding.Selection.EffectiveMode() == "manual" && fallback.Fallback == nil {
		request.PreferredModelVersionID = op.Policy.Model.ModelVersionID
		for _, candidate := range op.Policy.Model.Routing.Candidates {
			if candidate.ModelVersionID == request.PreferredModelVersionID {
				request.MinimumQualityRank = policyasset.ModelComplexityRank(candidate.MaxComplexity)
			}
		}
	}
	if fallback.Fallback != nil {
		if p.Availability == nil || !validModelRouteFallback(fallback.Fallback) || fallback.Fallback.Attempt >= p.Availability.MaxAttempts ||
			len(fallback.Excluded) != fallback.Fallback.Attempt {
			return nil, true, ErrModelInvocationConflict
		}
		request.MinimumQualityRank = fallback.Fallback.MinimumQualityRank
	}
	request.ReasoningMode, request.ReasoningEffort = op.Policy.Model.ReasoningMode, op.Policy.Model.ReasoningEffort
	request.TaskComplexity = binding.TaskComplexity
	base, err := modelCommandFingerprint(request.Messages, temperature, request.MaxTokens, promptHash, op.Policy.Model, request.FunctionNames, false, skills)
	if err != nil {
		return nil, true, err
	}
	raw, modeSchema, schemaErr := modelgateway.NormalizeResponseSchema(request.ResponseSchema, request.ResponseSchemaMode, request.RequireJSON, request.FunctionNames)
	if schemaErr != nil {
		return nil, true, schemaErr
	}
	request.ResponseSchema, request.ResponseSchemaMode = raw, modeSchema
	base = modelResponseSchemaFingerprint(base, raw, modeSchema)
	base = modelDeadlineFingerprint(base, request.DeadlineMS)
	request.Messages, _, err = m.invocationContext(*op, request.Messages, false)
	if err != nil {
		return nil, true, err
	}
	if op.Policy.Model.ContextCache != nil {
		request.ContextCacheMode = op.Policy.Model.ContextCache.Mode
		request.AllowUnreportedPrefixPreparation = op.Policy.Model.AllowsUnreportedPrefixPreparation()
	}
	requestHash := modelRouteHash(struct {
		Input, Policy, Routing, Task string
		RequireJSON                  bool
	}{base, op.Policy.Hash, modelRouteHash(p), binding.TaskSHA256, request.RequireJSON})
	stored, exists, err := store.LookupModelRoute(ctx, modelSelectionScopeHash(scope), key)
	if err != nil {
		return nil, true, err
	}
	if !exists {
		if lookupOnly {
			return nil, true, nil
		}
		at := time.Now().UTC()
		selectionMetadata := metadata
		if p.Availability != nil {
			healthStore, available := m.modelStore.(ModelRouteAvailabilityStore)
			if !available {
				return nil, true, ErrModelRouteUnavailable
			}
			selectionMetadata = availableRoutingMetadata{RoutingMetadataResolver: metadata, store: healthStore, at: at}
		}
		if fallback.Fallback != nil {
			selectionMetadata = fallbackRoutingMetadata{RoutingMetadataResolver: selectionMetadata, excluded: fallback.Excluded}
		}
		decision, err := SelectModelRoute(ctx, scope, p, request, op.Policy.Tool, op.Policy.Model.AllowExternal, selectionMetadata, m.modelPrices, at)
		if err != nil {
			return nil, true, err
		}
		decision.Fallback = fallback.Fallback
		if manualFallback && binding.Selection.EffectiveMode() == "manual" {
			decision.SelectionMode = "manual"
		}
		proposal := StoredModelRoute{RequestFingerprint: requestHash, Decision: decision, DecisionSHA256: modelRouteHash(decision)}
		stored, err = store.PersistModelRoute(ctx, modelSelectionScopeHash(scope), key, proposal)
		if err != nil {
			return nil, true, err
		}
	}
	features, err := classifyModelRoute(p, request, op.Policy.Tool)
	expectedMode := ""
	if manualFallback && binding.Selection.EffectiveMode() == "manual" {
		expectedMode = "manual"
	}
	if err != nil || !validStoredModelRoute(stored) || stored.RequestFingerprint != requestHash ||
		stored.Decision.SelectionMode != expectedMode ||
		stored.Decision.PolicySHA256 != modelRouteHash(p) || stored.Decision.FeaturesSHA256 != modelRouteHash(features) ||
		modelRouteHash(stored.Decision.Fallback) != modelRouteHash(fallback.Fallback) {
		return nil, true, ErrModelInvocationConflict
	}
	member := false
	mode, effort := "", ""
	for _, candidate := range p.Candidates {
		if candidate.ModelVersionID == stored.Decision.ModelVersionID && candidate.PriceVersionID == stored.Decision.Price.ID &&
			candidate.CapabilitySHA256 == stored.Decision.CapabilitySHA256 && candidate.QualityEvidenceSHA256 == stored.Decision.QualityEvidenceSHA256 &&
			policyasset.ModelComplexityRank(candidate.MaxComplexity) >= policyasset.ModelComplexityRank(features.Complexity) &&
			policyasset.ModelComplexityRank(candidate.MaxComplexity) >= request.MinimumQualityRank {
			member = true
			mode, effort = candidate.EffectiveReasoning(op.Policy.Model)
		}
	}
	if !member || stored.Decision.EstimatedMicros > p.MaxEstimatedMicros {
		return nil, true, ErrModelInvocationConflict
	}
	if traversal, _ := ctx.Value(modelRouteTraversalKey{}).(bool); traversal {
		return &stored, true, nil
	}
	model, err := metadata.ResolveRoutingModel(ctx, scope, stored.Decision.ModelVersionID)
	if err != nil {
		return nil, true, err
	}
	if model.CapabilitySHA256() != stored.Decision.CapabilitySHA256 || model.Selection.ModelVersionID != stored.Decision.ModelVersionID || model.Selection.ModelKey != stored.Decision.ModelKey ||
		model.Kind != modelgovernance.ModelKindChat || model.Selection.TrustZone == modelgovernance.TrustExternal && !op.Policy.Model.AllowExternal ||
		int64(model.ContextLimit) < features.InputTokenBound+int64(request.MaxTokens) ||
		len(request.FunctionNames) > 0 && !model.SupportsFunctions || request.RequireJSON && !model.SupportsJSON || len(request.ResponseSchema) > 0 && request.ResponseSchemaMode != "prefer_supported" && !modelgateway.SupportsResponseSchema(model.ResponseSchemaDialect) || modelgateway.ValidateWireReasoning(model.ReasoningDialect, mode, effort) != nil || !request.allowsContextCacheMode(model.ContextCacheMode) {
		return nil, true, modelgovernance.ErrModelAccessDenied
	}
	op.Policy.Model.ModelVersionID = model.Selection.ModelVersionID
	op.Policy.Model.Provider = model.Selection.ProviderKey
	op.Policy.Model.Model = model.Selection.ModelKey
	op.Policy.Model.ReasoningMode, op.Policy.Model.ReasoningEffort = mode, effort
	return &stored, true, nil
}

func modelRouteError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrModelInvocationConflict):
		return 409, "MODEL_IDEMPOTENCY_CONFLICT"
	case errors.Is(err, ErrModelRouteNoCandidate):
		return 409, "MODEL_ROUTE_NO_CANDIDATE"
	case errors.Is(err, ErrModelRouteInvalidRequest):
		return 400, "MODEL_ROUTE_REQUEST_INVALID"
	case errors.Is(err, modelgovernance.ErrModelAccessDenied), errors.Is(err, modelgovernance.ErrForbidden), errors.Is(err, modelgovernance.ErrNotFound):
		return 403, "MODEL_ACCESS_DENIED"
	default:
		return 503, "MODEL_ROUTING_UNAVAILABLE"
	}
}

// modelRouteReceipt contains policy/price/quality references and bounded reasons,
// never messages, endpoints, credentials or rejected provider error bodies.
func modelRouteReceipt(route StoredModelRoute) map[string]any {
	d := route.Decision
	result := map[string]any{"version": "model-route-receipt/v1", "mode": "automatic",
		"decision_sha256": route.DecisionSHA256, "policy_sha256": d.PolicySHA256,
		"model_version_id": d.ModelVersionID, "price_version_id": d.Price.ID,
		"model_key":  d.ModelKey,
		"complexity": d.Features.Complexity, "reasons": append([]string(nil), d.Features.Reasons...),
		"estimated_micros": d.EstimatedMicros, "quality_evidence_sha256": d.QualityEvidenceSHA256,
		"excluded": append([]ModelRouteExclusion(nil), d.Excluded...)}
	if d.Fallback != nil {
		result["fallback"] = *d.Fallback
	}
	if d.SelectionMode == "manual" {
		result["mode"] = "manual"
	}
	return result
}
