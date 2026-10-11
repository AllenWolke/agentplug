package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func seedRuntimeIndexModel(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope) string {
	principal := s.PrincipalID
	return seedRuntimeApprovedModel(t, ctx, db, s, "index-process", modelgovernance.ModelKindEmbedding, &principal)
}

func seedRuntimeApprovedModel(t *testing.T, ctx context.Context, db *sql.DB, s sharedkernel.Scope, prefix, kind string, accessPrincipal *string, targets ...runtimeModelTarget) string {
	t.Helper()
	target := runtimeModelTarget{Model: prefix + "-model", SecretFile: "provider.key"}
	if len(targets) == 1 {
		target = targets[0]
	} else if len(targets) != 0 {
		t.Fatal("one model target required")
	}
	store := modelgovernance.NewSQLStore(db)
	provider := modelgovernance.Provider{ID: indexProcessUUID(t), ProviderKey: prefix + "-provider", DisplayName: "Index process", Type: modelgovernance.ProviderOnPrem, TrustZone: modelgovernance.TrustLocal, EndpointRef: "service://" + prefix + "-model", OwnerID: s.PrincipalID, SecretRef: "secret://provider.key", RetentionMode: "disabled", TrainingUsage: "disabled", ComplianceStatus: "approved", Capabilities: []byte(`{"embedding":true,"chat":true}`), Status: modelgovernance.StatusDraft, HealthStatus: "unknown", Revision: 1}
	provider.SecretRef = "secret://" + target.SecretFile
	if target.Live {
		provider.Type, provider.TrustZone = modelgovernance.ProviderExternalManaged, modelgovernance.TrustExternal
	}
	if err := store.CreateProvider(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateProviderStatus(ctx, provider.ID, 1, modelgovernance.StatusApproved); err != nil {
		t.Fatal(err)
	}
	model := modelgovernance.ModelDefinition{ID: indexProcessUUID(t), ProviderID: provider.ID, ModelKey: prefix + "-model", Kind: kind, DisplayName: "Index vectors", Capabilities: []byte(`{"embedding":true,"chat":true}`), ContextLimit: 4096, LifecycleStatus: modelgovernance.StatusDraft, Revision: 1}
	model.ModelKey = target.Model
	if err := store.CreateDefinition(ctx, &model); err != nil {
		t.Fatal(err)
	}
	version := modelgovernance.ModelVersion{ID: indexProcessUUID(t), DefinitionID: model.ID, SemanticVersion: "1.0.0", ProviderFingerprint: "index-process-embedding", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), Status: modelgovernance.StatusDraft, Revision: 1}
	if err := store.CreateVersion(ctx, &version); err != nil {
		t.Fatal(err)
	}
	if err := store.ApproveVersion(ctx, version.ID, 1); err != nil {
		t.Fatal(err)
	}
	price := modelgovernance.PriceVersion{ID: indexProcessUUID(t), ModelVersionID: version.ID, Currency: "USD", InputMicrosPer1K: 100000, OutputMicrosPer1K: 100000, EffectiveFrom: time.Now().UTC().Add(-time.Hour), Status: modelgovernance.StatusDraft, Revision: 1, CreatedBy: s.PrincipalID}
	raw, err := json.Marshal(struct {
		ModelVersionID    string     `json:"model_version_id"`
		Currency          string     `json:"currency"`
		InputMicrosPer1K  int64      `json:"input_micros_per_1k_tokens"`
		OutputMicrosPer1K int64      `json:"output_micros_per_1k_tokens"`
		EffectiveFrom     time.Time  `json:"effective_from"`
		EffectiveUntil    *time.Time `json:"effective_until,omitempty"`
	}{price.ModelVersionID, price.Currency, price.InputMicrosPer1K, price.OutputMicrosPer1K, price.EffectiveFrom, nil})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	price.ContentHash = "sha256:" + hex.EncodeToString(h[:])
	if err := store.CreatePriceVersion(ctx, &price); err != nil {
		t.Fatal(err)
	}
	if err := store.ApprovePriceVersion(ctx, price.ID, 1); err != nil {
		t.Fatal(err)
	}
	deployment := modelgovernance.Deployment{ID: indexProcessUUID(t), TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, ModelVersionID: version.ID, Environment: "development", EndpointRef: provider.EndpointRef, RuntimeKind: "http", ResourceProfile: []byte(`{}`), MinReplicas: 1, MaxReplicas: 1, Capacity: []byte(`{"max_concurrent_requests":2}`), HealthStatus: "unknown", Status: "pending", Revision: 1}
	if err := store.CreateDeployment(ctx, &deployment); err != nil {
		t.Fatal(err)
	}
	scope := modelgovernance.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID}
	if err := store.UpdateDeploymentHealth(ctx, scope, deployment.ID, 1, "ready", "ready"); err != nil {
		t.Fatal(err)
	}
	if accessPrincipal == nil {
		return version.ID
	}
	start := time.Now().UTC().Add(-time.Minute)
	policy := modelgovernance.AccessPolicy{ID: indexProcessUUID(t), TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, InstallationID: s.InstallationID, AgentVersionID: s.AgentVersionID, PrincipalID: *accessPrincipal, AllowLocal: true, AllowedProviders: []string{provider.ID}, AllowedModels: []string{model.ID}, EffectiveFrom: &start, Status: modelgovernance.PolicyDraft, Revision: 1}
	if err := store.CreateAccessPolicy(ctx, &policy); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateAccessPolicyStatus(ctx, scope, policy.ID, 1, modelgovernance.PolicyApproved); err != nil {
		t.Fatal(err)
	}
	return version.ID
}
