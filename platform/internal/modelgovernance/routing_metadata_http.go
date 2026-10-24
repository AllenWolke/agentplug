package modelgovernance

import "net/http"

func (m *Module) routingMetadataReceipt(w http.ResponseWriter, r *http.Request, definitionID, versionID string) {
	if r.Method != http.MethodGet {
		m.error(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if _, ok := m.authorize(w, r, ActionRead); !ok {
		return
	}
	if _, err := m.store.GetVersion(r.Context(), definitionID, versionID); err != nil {
		m.storeError(w, err)
		return
	}
	metadata, err := ApprovedRoutingMetadata(r.Context(), m.store, versionID)
	if err != nil {
		m.storeError(w, err)
		return
	}
	m.json(w, http.StatusOK, map[string]any{
		"version": "model-routing-metadata-receipt/v1", "model_version_id": versionID,
		"model_id": metadata.Selection.ModelID, "model_key": metadata.Selection.ModelKey,
		"provider_id": metadata.Selection.ProviderID, "provider_key": metadata.Selection.ProviderKey,
		"trust_zone": metadata.Selection.TrustZone, "context_limit": metadata.ContextLimit,
		"function_calling": metadata.SupportsFunctions, "json_output": metadata.SupportsJSON,
		"wire_model": metadata.WireModel, "reasoning_dialect": metadata.ReasoningDialect,
		"context_cache_mode":      metadata.ContextCacheMode,
		"response_schema_dialect": metadata.ResponseSchemaDialect,
		"capability_sha256":       metadata.CapabilitySHA256(), "inference_authorized": false,
	})
}
