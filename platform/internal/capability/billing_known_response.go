package capability

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
)

// Existing common catalog reads, not an Agent-specific accounting implementation.
type knownBillingCatalog interface {
	GetPriceVersion(context.Context, string) (modelgovernance.PriceVersion, error)
	GetResolvedVersion(context.Context, string) (modelgovernance.ResolvedModel, error)
}

func measuredTokenCount(value any) (int, bool) {
	var n int64
	switch v := value.(type) {
	case int:
		n = int64(v)
	case int64:
		n = v
	case json.Number:
		var err error
		n, err = v.Int64()
		if err != nil {
			return 0, false
		}
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > float64(1<<53-1) || math.Trunc(v) != v {
			return 0, false
		}
		n = int64(v)
	default:
		return 0, false
	}
	if n < 0 || uint64(n) > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(n), true
}

// Resume only authentic saved responses with an exact original catalog/price
// binding. Missing responses or unmeasured differential pricing stay manual.
// This function has no provider call, admission or replacement-model branch.
func (m *Module) resumeKnownBilling(ctx context.Context, record ModelInvocation) error {
	store, ok := m.modelStore.(ModelBillingRecoveryStore)
	catalog, supported := m.modelPrices.(knownBillingCatalog)
	if !ok || !supported || record.Status != "reconcile" || record.RecoveryCorrupt || record.Recovery == nil || record.Response == nil || record.Recovery.Event != nil || record.Recovery.Decision != nil || record.Recovery.Unsent || !record.Recovery.SendDeadline.IsZero() || record.Recovery.PriceID != record.Recovery.Reservation.PriceVersionID {
		return ErrModelInvocationConflict
	}
	response := cloneMap(record.Response)
	version, _ := response["model_version_id"].(string)
	providerID, _ := response["provider_id"].(string)
	modelID, _ := response["model_id"].(string)
	modelKey, _ := response["model"].(string)
	if version == "" || providerID == "" || modelID == "" || modelKey == "" {
		return ErrModelInvocationConflict
	}
	price, err := catalog.GetPriceVersion(ctx, record.Recovery.PriceID)
	if err != nil {
		return err
	}
	if price.ID != record.Recovery.PriceID || price.ModelVersionID != version || price.Status != "approved" || price.Currency != "USD" {
		return ErrModelInvocationConflict
	}
	model, err := catalog.GetResolvedVersion(ctx, version)
	if err != nil {
		return err
	}
	if model.VersionID != version || model.DefinitionID != modelID || model.ProviderID != providerID || model.ModelKey != modelKey || model.ProviderKey == "" || model.Kind != "chat" || model.VersionStatus != "approved" || model.ProviderStatus != "approved" {
		return ErrModelInvocationConflict
	}
	usage, ok := response["usage"].(map[string]any)
	if !ok {
		return errors.New("saved provider usage unavailable")
	}
	input, inputKnown := measuredTokenCount(usage["input_tokens"])
	output, outputKnown := measuredTokenCount(usage["output_tokens"])
	if !inputKnown || !outputKnown {
		return errors.New("saved provider token counts unavailable")
	}
	var cached *int
	_, cachedPresent := usage["cached_input_tokens"]
	_, uncachedPresent := usage["uncached_input_tokens"]
	if cachedPresent != uncachedPresent {
		return errors.New("incomplete saved cache split")
	}
	if raw, exists := usage["cached_input_tokens"]; exists {
		count, known := measuredTokenCount(raw)
		miss, missKnown := measuredTokenCount(usage["uncached_input_tokens"])
		if !known || !missKnown || count > input || miss != input-count {
			return errors.New("invalid saved cache split")
		}
		cached = &count
	}
	cost, err := approvedModelCacheCost(price, int64(input), int64(output), cached)
	if err != nil {
		return err
	}
	r := record.Recovery.Reservation
	if r.Scope.TenantID == "" || r.Scope.DepartmentID == "" || r.Scope.ApplicationID == "" || r.Scope.AgentID == "" || r.Scope.AgentVersionID == "" || r.RunID == "" || r.RequestID == "" || r.Fingerprint != record.Fingerprint {
		return ErrModelInvocationConflict
	}
	h := harnessContext{TenantID: r.Scope.TenantID, DepartmentID: r.Scope.DepartmentID, ApplicationID: r.Scope.ApplicationID, AgentID: r.Scope.AgentID, AgentVersionID: r.Scope.AgentVersionID, TaskID: r.RunID}
	event, err := buildModelUsageEvent(h, modelgateway.Selection{ProviderKey: model.ProviderKey, ModelKey: model.ModelKey}, input, output, cost, record.Key)
	if err != nil {
		return err
	}
	billing := map[string]any{"price_version_id": price.ID, "currency": price.Currency, "cost_micros": cost, "cache_usage_known": cached != nil, "pricing_mode": "uniform_input"}
	if price.CachedInputMicrosPer1K != nil {
		billing["pricing_mode"] = "cached_input"
		billing["cached_input_micros_per_1k_tokens"] = *price.CachedInputMicrosPer1K
		cold, coldErr := approvedModelCost(price, int64(input), int64(output))
		if coldErr != nil {
			return coldErr
		}
		billing["cache_savings_micros"] = cold - cost
	}
	response["billing"] = billing
	if event.StepID != nil {
		response["step_id"] = *event.StepID
	}
	recovery := *record.Recovery
	recovery.Event = &event
	return store.SaveBillingRecovery(ctx, record.ScopeHash, record.Key, record.Fingerprint, response, ceilModelCostCents(cost), recovery)
}
