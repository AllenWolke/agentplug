package modelgovernance

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ResolveRoutingModel reuses live approval, scoped access and local capacity.
// It does not create an alternate authorization or deployment path.
func (r AccessResolver) ResolveRoutingModel(ctx context.Context, scope sharedkernel.Scope, versionID string) (modelgateway.RoutingMetadata, error) {
	selection, err := r.ResolveModel(ctx, scope, versionID)
	if err != nil {
		return modelgateway.RoutingMetadata{}, err
	}
	return routingMetadata(ctx, r.Store, selection)
}

// ApprovedRoutingMetadata is a catalog projection for publication tools. It
// does not authorize inference or assert that a local deployment is ready.
// Invocation still goes through AccessResolver and the existing capacity port.
func ApprovedRoutingMetadata(ctx context.Context, store Store, versionID string) (modelgateway.RoutingMetadata, error) {
	if store == nil || !validGovernanceID(versionID, 128) {
		return modelgateway.RoutingMetadata{}, ErrInvalidRequest
	}
	resolved, err := store.GetResolvedVersion(ctx, versionID)
	if err != nil {
		return modelgateway.RoutingMetadata{}, err
	}
	if resolved.VersionID != versionID || resolved.VersionStatus != StatusApproved || resolved.ProviderStatus != StatusApproved {
		return modelgateway.RoutingMetadata{}, ErrModelAccessDenied
	}
	return routingMetadata(ctx, store, modelgateway.Selection{ModelVersionID: resolved.VersionID,
		ProviderID: resolved.ProviderID, ProviderKey: resolved.ProviderKey, ModelID: resolved.DefinitionID,
		ModelKey: resolved.ModelKey, TrustZone: resolved.TrustZone})
}

func routingMetadata(ctx context.Context, store Store, selection modelgateway.Selection) (modelgateway.RoutingMetadata, error) {
	definition, err := store.GetDefinition(ctx, selection.ModelID)
	if err != nil {
		return modelgateway.RoutingMetadata{}, err
	}
	if definition.ID != selection.ModelID || definition.ProviderID != selection.ProviderID ||
		definition.ModelKey != selection.ModelKey || definition.Kind != ModelKindChat ||
		definition.LifecycleStatus != StatusDraft || definition.ContextLimit <= 0 {
		return modelgateway.RoutingMetadata{}, ErrModelAccessDenied
	}
	var capabilities struct {
		Functions bool `json:"function_calling"`
		JSON      bool `json:"json_output"`
	}
	if json.Unmarshal(definition.Capabilities, &capabilities) != nil {
		return modelgateway.RoutingMetadata{}, ErrModelAccessDenied
	}
	wire, err := modelgateway.ParseWireCapabilities(definition.Capabilities)
	if err != nil {
		return modelgateway.RoutingMetadata{}, ErrModelAccessDenied
	}
	return modelgateway.RoutingMetadata{Selection: selection, Kind: definition.Kind,
		ResponseSchemaDialect: wire.ResponseSchemaDialect,
		ContextCacheMode:      wire.ContextCacheMode,
		ContextLimit:          definition.ContextLimit, SupportsFunctions: capabilities.Functions, SupportsJSON: capabilities.JSON,
		WireModel: wire.WireModel, ReasoningDialect: wire.ReasoningDialect}, nil
}

var _ modelgateway.RoutingMetadataResolver = AccessResolver{}
