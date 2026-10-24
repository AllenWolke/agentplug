package modelgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
)

func TestRoutingMetadataReusesScopeApprovalAndManagedCapacity(t *testing.T) {
	store := newMemoryStore()
	store.providers["provider-id"] = Provider{ID: "provider-id", ProviderKey: "local-provider", TrustZone: TrustLocal, Status: StatusApproved}
	store.definitions["model-id"] = ModelDefinition{ID: "model-id", ProviderID: "provider-id", ModelKey: "qa-model", Kind: ModelKindChat, LifecycleStatus: StatusDraft, ContextLimit: 8192, Capabilities: json.RawMessage(`{"function_calling":true,"json_output":true}`)}
	store.versions["version-id"] = ModelVersion{ID: "version-id", DefinitionID: "model-id", Status: StatusApproved}
	store.policies["policy-id"] = AccessPolicy{ID: "policy-id", TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app", InstallationID: "installation-a", AgentVersionID: "agent-version-a", PrincipalID: "user-a", AllowLocal: true, AllowedProviders: []string{"provider-id"}, AllowedModels: []string{"model-id"}, Status: PolicyApproved, EffectiveFrom: timePtr(time.Now().UTC().Add(-time.Minute))}
	capacity := testCapacityResolver{deployment: modelcapacity.RuntimeDeployment{ID: "deployment-a", ModelVersionID: "version-id", EndpointRef: "service://local-deployment", CapacityUnits: 1, HealthStatus: "ready", Status: DeploymentReady}}
	resolver := AccessResolver{Store: store, Capacity: capacity}
	metadata, err := resolver.ResolveRoutingModel(context.Background(), trustedModelScope(), "version-id")
	if err != nil || !metadata.SupportsFunctions || !metadata.SupportsJSON || metadata.ContextLimit != 8192 {
		t.Fatal("approved capabilities were not resolved")
	}
	wrong := trustedModelScope()
	wrong.PrincipalID = "user-b"
	if _, err = resolver.ResolveRoutingModel(context.Background(), wrong, "version-id"); !errors.Is(err, ErrModelAccessDenied) {
		t.Fatal("routing bypassed scope authorization")
	}
	resolver.Capacity = nil
	if _, err = resolver.ResolveRoutingModel(context.Background(), trustedModelScope(), "version-id"); !errors.Is(err, modelcapacity.ErrUnavailable) {
		t.Fatal("routing bypassed managed local deployment")
	}
	resolver.Capacity = capacity
	d := store.definitions["model-id"]
	d.Kind = ModelKindEmbedding
	store.definitions["model-id"] = d
	if _, err = resolver.ResolveRoutingModel(context.Background(), trustedModelScope(), "version-id"); !errors.Is(err, ErrModelAccessDenied) {
		t.Fatal("embedding entered chat pool")
	}
}
