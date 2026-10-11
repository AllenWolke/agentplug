package modelgovernance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestAccessResolverRequiresApprovedVersionAndMatchingScopePolicy(t *testing.T) {
	store := newMemoryStore()
	store.providers["provider-id"] = Provider{ID: "provider-id", ProviderKey: "local-provider", TrustZone: TrustLocal, Status: StatusApproved}
	store.definitions["model-id"] = ModelDefinition{ID: "model-id", ProviderID: "provider-id", ModelKey: "qa-model"}
	store.versions["version-id"] = ModelVersion{ID: "version-id", DefinitionID: "model-id", Status: StatusApproved}
	store.policies["policy-id"] = AccessPolicy{
		ID: "policy-id", TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app",
		InstallationID: "installation-a", AgentVersionID: "agent-version-a", PrincipalID: "user-a",
		AllowLocal: true, AllowedProviders: []string{"provider-id"}, AllowedModels: []string{"model-id"},
		Status: PolicyApproved, EffectiveFrom: timePtr(time.Now().UTC().Add(-time.Minute)),
	}

	capacity := testCapacityResolver{deployment: modelcapacity.RuntimeDeployment{ID: "deployment-a", ModelVersionID: "version-id", EndpointRef: "service://local-deployment", CapacityUnits: 4, HealthStatus: "ready", Status: DeploymentReady}}
	resolver := AccessResolver{Store: store, Capacity: capacity}
	scope := trustedModelScope()
	selection, err := resolver.ResolveModel(context.Background(), scope, "version-id")
	if err != nil {
		t.Fatalf("approved model and matching policy should resolve: %v", err)
	}
	if selection.ModelVersionID != "version-id" || selection.ProviderID != "provider-id" || selection.ProviderKey != "local-provider" || selection.ModelID != "model-id" || selection.ModelKey != "qa-model" || selection.TrustZone != TrustLocal || selection.DeploymentID != "deployment-a" || selection.EndpointRef != "service://local-deployment" || selection.CapacityUnits != 4 {
		t.Fatalf("resolver returned incomplete or wrong catalog selection: %+v", selection)
	}

	wrongPrincipal := scope
	wrongPrincipal.PrincipalID = "user-b"
	if _, err := resolver.ResolveModel(context.Background(), wrongPrincipal, "version-id"); !errors.Is(err, ErrModelAccessDenied) {
		t.Fatalf("policy for another user must not authorize: %v", err)
	}
	wrongApplication := scope
	wrongApplication.ApplicationID = "aml"
	if _, err := resolver.ResolveModel(context.Background(), wrongApplication, "version-id"); !errors.Is(err, ErrModelAccessDenied) {
		t.Fatalf("policy for another application must not authorize: %v", err)
	}
	if _, err := resolver.ResolveModel(context.Background(), scope, "unknown-version"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown model version must not resolve: %v", err)
	}

	store.versions["version-id"] = ModelVersion{ID: "version-id", DefinitionID: "model-id", Status: StatusDraft}
	if _, err := resolver.ResolveModel(context.Background(), scope, "version-id"); !errors.Is(err, ErrModelAccessDenied) {
		t.Fatalf("unapproved model version must be denied: %v", err)
	}
}

type testCapacityResolver struct {
	deployment modelcapacity.RuntimeDeployment
	err        error
}

func (r testCapacityResolver) ResolveReadyDeployment(context.Context, sharedkernel.Scope, string) (modelcapacity.RuntimeDeployment, error) {
	return r.deployment, r.err
}

func TestAccessResolverFailsClosedWhenLocalDeploymentCapacityIsMissing(t *testing.T) {
	store := newMemoryStore()
	store.providers["provider-id"] = Provider{ID: "provider-id", ProviderKey: "local-provider", TrustZone: TrustLocal, Status: StatusApproved}
	store.definitions["model-id"] = ModelDefinition{ID: "model-id", ProviderID: "provider-id", ModelKey: "qa-model"}
	store.versions["version-id"] = ModelVersion{ID: "version-id", DefinitionID: "model-id", Status: StatusApproved}
	store.policies["policy-id"] = AccessPolicy{ID: "policy-id", TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app", InstallationID: "installation-a", AgentVersionID: "agent-version-a", PrincipalID: "user-a", AllowLocal: true, AllowedProviders: []string{"provider-id"}, AllowedModels: []string{"model-id"}, Status: PolicyApproved, EffectiveFrom: timePtr(time.Now().UTC().Add(-time.Minute))}
	if _, err := (AccessResolver{Store: store}).ResolveModel(context.Background(), trustedModelScope(), "version-id"); !errors.Is(err, modelcapacity.ErrUnavailable) {
		t.Fatalf("local model without an active capacity pool must fail closed: %v", err)
	}
}

func TestAccessResolverRejectsIncompleteTrustedExecutionScope(t *testing.T) {
	resolver := AccessResolver{Store: newMemoryStore()}
	if _, err := resolver.ResolveModel(context.Background(), sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "d", ApplicationID: "a", PrincipalID: "user-a"}, "version-id"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("incomplete execution context should fail closed: %v", err)
	}
}

func trustedModelScope() sharedkernel.Scope {
	return sharedkernel.Scope{
		TenantID: "tenant-a", DepartmentID: "compliance", ApplicationID: "business-app",
		AgentInstanceID: "instance-a", AgentID: "document-assistant", PrincipalID: "user-a", PrincipalType: "user",
		InstallationID: "installation-a", AgentVersionID: "agent-version-a", SessionID: "session-a", RunID: "run-a",
		AuthorizationEpoch: 1, TraceID: "trace-a",
	}
}

func timePtr(value time.Time) *time.Time { return &value }
