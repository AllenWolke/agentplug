package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type indexBillingAccess struct{ selection modelgateway.Selection }

func (f indexBillingAccess) ResolveModel(_ context.Context, _ sharedkernel.Scope, version string) (modelgateway.Selection, error) {
	if version != f.selection.ModelVersionID {
		return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
	}
	return f.selection, nil
}

type indexBillingSecret struct{}

func (indexBillingSecret) ResolveSecret(context.Context, string) ([]byte, error) {
	return []byte("integration-secret"), nil
}

type indexSQLBilling struct {
	governance  *modelgovernance.SQLStore
	usage       *usagecost.SQLStore
	invocations *capability.SQLModelInvocationStore
	capacity    *modelcapacity.SQLProvider
	gateway     modelgateway.Port
	access      modelgateway.AccessResolver
	calls       *atomic.Int32
}

func indexFixtureUUID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
}
func newIndexSQLBilling(t *testing.T, admin, db *sql.DB, actor sharedkernel.Scope, snapshot *policyasset.Snapshot) *indexSQLBilling {
	t.Helper()
	ctx := context.Background()
	for _, ensure := range []func(context.Context) error{modelgovernance.NewSQLStore(admin).EnsureSchema, usagecost.NewSQLStore(admin).EnsureSchema, modelcapacity.NewSQLProvider(admin).EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	adminInv, err := capability.NewSQLModelInvocationStore(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminInv.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	governance := modelgovernance.NewSQLStore(db)
	usage := usagecost.NewSQLStore(db)
	capacity := modelcapacity.NewSQLProvider(db)
	invocations, err := capability.NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	providerID, definitionID, versionID, priceID, deploymentID := indexFixtureUUID(t), indexFixtureUUID(t), indexFixtureUUID(t), indexFixtureUUID(t), indexFixtureUUID(t)
	providerKey, modelKey := "index-provider-"+providerID[:8], "index-model-"+definitionID[:8]
	tenantID, departmentID, applicationID := actor.TenantID, actor.DepartmentID, actor.ApplicationID
	endpointRef := "service://index-upstream-" + providerID[:8]
	secretRef := "secret://billing/" + providerID
	provider := modelgovernance.Provider{
		ID: providerID, ProviderKey: providerKey, DisplayName: "Billing Integration Provider",
		Type: modelgovernance.ProviderOnPrem, TrustZone: modelgovernance.TrustLocal,
		EndpointRef: endpointRef, OwnerID: "integration-admin", SecretRef: secretRef,
		RetentionMode: "disabled", TrainingUsage: "disabled", ComplianceStatus: "approved",
		Capabilities: json.RawMessage(`{"chat":true}`), Status: modelgovernance.StatusDraft,
		HealthStatus: "unknown", Revision: 1,
	}
	if err = governance.CreateProvider(ctx, &provider); err != nil {
		t.Fatalf("create SQL provider fixture: %v", err)
	}
	if err = governance.UpdateProviderStatus(ctx, providerID, 1, modelgovernance.StatusApproved); err != nil {
		t.Fatalf("approve SQL provider fixture: %v", err)
	}
	definition := modelgovernance.ModelDefinition{
		ID: definitionID, ProviderID: providerID, ModelKey: modelKey, Kind: func() string {
			if true {
				return modelgovernance.ModelKindEmbedding
			}
			return modelgovernance.ModelKindChat
		}(),
		DisplayName: "Billing Integration Model", Capabilities: json.RawMessage(`{"chat":true}`),
		ContextLimit: 4096, LifecycleStatus: modelgovernance.StatusDraft, Revision: 1,
	}
	if err = governance.CreateDefinition(ctx, &definition); err != nil {
		t.Fatalf("create SQL model definition fixture: %v", err)
	}
	version := modelgovernance.ModelVersion{
		ID: versionID, DefinitionID: definitionID, SemanticVersion: "1.0.0",
		ProviderFingerprint: "billing-e2e", ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		Status: modelgovernance.StatusDraft, Revision: 1,
	}
	if err = governance.CreateVersion(ctx, &version); err != nil {
		t.Fatalf("create SQL model version fixture: %v", err)
	}
	if err = governance.ApproveVersion(ctx, versionID, 1); err != nil {
		t.Fatalf("approve SQL model version fixture: %v", err)
	}

	price := modelgovernance.PriceVersion{
		ID: priceID, ModelVersionID: versionID, Currency: "USD",
		InputMicrosPer1K: 100_000, OutputMicrosPer1K: 100_000,
		EffectiveFrom: time.Now().UTC().Add(-time.Hour), Status: modelgovernance.StatusDraft,
		Revision: 1, CreatedBy: "integration-admin",
	}
	price.ContentHash = indexBillingPriceHash(t, price)
	if err = governance.CreatePriceVersion(ctx, &price); err != nil {
		t.Fatalf("create SQL price version fixture: %v", err)
	}
	if err = governance.ApprovePriceVersion(ctx, priceID, 1); err != nil {
		t.Fatalf("approve SQL price version fixture: %v", err)
	}

	modelScope := sharedkernel.Scope{TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID}
	deployment := modelcapacity.Deployment{
		ID: deploymentID, TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID,
		ModelVersionID: versionID, CapacityUnits: 2,
	}
	capacityTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = modelcapacity.RegisterPoolTx(capacityTx, deployment, time.Now().UTC()); err != nil {
		_ = capacityTx.Rollback()
		t.Fatalf("register local model capacity fixture: %v", err)
	}
	if err = modelcapacity.UpdatePoolStateTx(capacityTx, modelScope, deploymentID, "ready", "ready", time.Now().UTC()); err != nil {
		_ = capacityTx.Rollback()
		t.Fatalf("ready local model capacity fixture: %v", err)
	}
	if err = capacityTx.Commit(); err != nil {
		t.Fatal(err)
	}

	snapshot.Model.ModelVersionID = versionID
	snapshot.Model.Provider = providerKey
	snapshot.Model.Model = modelKey
	snapshot.Model.BudgetCents = 1
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/embeddings" || r.Header.Get("Authorization") != "Bearer integration-secret" {
			http.Error(w, "invalid guarded request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var request struct {
			Input []string `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Input) == 0 || len(request.Input) > 128 {
			http.Error(w, "invalid embedding batch", 400)
			return
		}
		data := make([]map[string]any, len(request.Input))
		for i := range data {
			data[i] = map[string]any{"index": i, "embedding": []float32{1, .5}}
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data, "usage": map[string]int{"prompt_tokens": 50, "total_tokens": 50}})
	}))
	t.Cleanup(server.Close)
	access := indexBillingAccess{selection: modelgateway.Selection{ModelVersionID: versionID, ProviderID: providerID, ProviderKey: providerKey, ModelID: definitionID, ModelKey: modelKey, TrustZone: modelgovernance.TrustLocal, DeploymentID: deploymentID, EndpointRef: endpointRef, CapacityUnits: 1}}
	gateway, err := modelgateway.NewHTTPAdapter(modelgateway.HTTPConfig{SecretRoot: t.TempDir(), AllowLoopbackDevelopment: true}, access, governance, governance, indexBillingSecret{}, modelgateway.StaticEndpointResolver{endpointRef: server.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	return &indexSQLBilling{governance: governance, usage: usage, invocations: invocations, capacity: capacity, gateway: gateway, access: access, calls: calls}
}
func indexBillingPriceHash(t *testing.T, p modelgovernance.PriceVersion) string {
	t.Helper()
	raw, err := json.Marshal(struct {
		ModelVersionID    string     `json:"model_version_id"`
		Currency          string     `json:"currency"`
		InputMicrosPer1K  int64      `json:"input_micros_per_1k_tokens"`
		OutputMicrosPer1K int64      `json:"output_micros_per_1k_tokens"`
		EffectiveFrom     time.Time  `json:"effective_from"`
		EffectiveUntil    *time.Time `json:"effective_until,omitempty"`
	}{p.ModelVersionID, p.Currency, p.InputMicrosPer1K, p.OutputMicrosPer1K, p.EffectiveFrom.UTC(), p.EffectiveUntil})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
