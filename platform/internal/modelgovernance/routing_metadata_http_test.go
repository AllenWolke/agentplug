package modelgovernance

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRoutingMetadataReceiptUsesNativeCatalogDigestWithoutInferenceAuthority(t *testing.T) {
	store := newMemoryStore()
	store.providers["provider-id"] = Provider{ID: "provider-id", ProviderKey: "private-provider", TrustZone: TrustPrivate, Status: StatusApproved, SecretRef: "secret://never-disclose", EndpointRef: "service://never-disclose"}
	store.definitions["model-id"] = ModelDefinition{ID: "model-id", ProviderID: "provider-id", ModelKey: "model-alias", Kind: ModelKindChat, LifecycleStatus: StatusDraft, ContextLimit: 8192, Capabilities: json.RawMessage(`{"function_calling":true,"json_output":true,"wire_model":"actual-model"}`)}
	store.versions["version-id"] = ModelVersion{ID: "version-id", DefinitionID: "model-id", Status: StatusApproved}
	called := 0
	module := moduleForTest(store, func(_ context.Context, actor Actor, action Action, scope Scope) error {
		called++
		if action != ActionRead || !scope.IsGlobal() || actor.PrincipalID != "admin-a" {
			t.Error("catalog receipt bypassed ordinary read authorization")
		}
		return nil
	})
	path := "/models/model-id/versions/version-id/routing-metadata"
	response := browserRequest(module.Handler(), http.MethodGet, path, "", nil)
	var receipt struct {
		Version   string `json:"version"`
		SHA       string `json:"capability_sha256"`
		Inference bool   `json:"inference_authorized"`
	}
	metadata, err := ApprovedRoutingMetadata(context.Background(), store, "version-id")
	if response.Code != 200 || err != nil || json.Unmarshal(response.Body.Bytes(), &receipt) != nil ||
		receipt.Version != "model-routing-metadata-receipt/v1" || receipt.SHA != metadata.CapabilitySHA256() || receipt.Inference || called != 1 {
		t.Fatal("native catalog projection was not returned")
	}
	if strings.Contains(response.Body.String(), "never-disclose") {
		t.Fatal("secret or endpoint escaped catalog projection")
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if browserRequest(module.Handler(), method, path, "{}", nil).Code != 405 {
			t.Fatal("metadata receipt mutated catalog")
		}
	}
	if browserRequest(module.Handler(), http.MethodGet, "/models/wrong-model/versions/version-id/routing-metadata", "", nil).Code != 404 {
		t.Fatal("foreign definition accepted")
	}
	provider := store.providers["provider-id"]
	provider.Status = StatusDisabled
	store.providers[provider.ID] = provider
	if browserRequest(module.Handler(), http.MethodGet, path, "", nil).Code != 403 {
		t.Fatal("disabled provider retained usable metadata")
	}
}

func TestRoutingMetadataReceiptDeniesRevokedReader(t *testing.T) {
	module := moduleForTest(newMemoryStore(), func(context.Context, Actor, Action, Scope) error { return ErrForbidden })
	if browserRequest(module.Handler(), http.MethodGet, "/models/model-id/versions/version-id/routing-metadata", "", nil).Code != 403 {
		t.Fatal("revoked reader could resolve catalog metadata")
	}
}
