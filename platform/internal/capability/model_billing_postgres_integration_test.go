package capability

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelcapacity"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// TestGovernedModelBillingPostgresIntegration verifies the production Capability
// path against real PostgreSQL ledgers and the real guarded HTTP Model Gateway.
// The upstream is a deterministic OpenAI-compatible test server; no live LLM
// or external network is needed to validate billing state transitions.
func TestGovernedModelBillingPostgresIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, false)
}
func TestGovernedEmbeddingBillingPostgresIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, true)
}
func TestGovernedKnowledgeEmbeddingBillingPostgresIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, true, true)
}
func TestGovernedFunctionBillingPostgresIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, false, false, true)
}
func TestInvalidFunctionBillingPostgresIntegration(t *testing.T) {
	testGovernedModelBillingPostgres(t, false, false, true, true)
}
func testGovernedModelBillingPostgres(t *testing.T, embedding bool, throughKnowledge ...bool) {
	knowledgeCall := len(throughKnowledge) > 0 && throughKnowledge[0]
	functionCall := len(throughKnowledge) > 1 && throughKnowledge[1]
	invalidFunction := len(throughKnowledge) > 2 && throughKnowledge[2]
	expectedStatus := http.StatusOK
	operation := "/internal/model/generate"
	expectedCost := int64(7000)
	expectedOutput := int64(20)
	expectedResult := "budget integration answer"
	if functionCall {
		expectedResult = "runtime.inspect"
		if invalidFunction {
			expectedStatus = http.StatusBadGateway
			expectedResult = "MODEL_FUNCTION_INVALID"
		}
	}
	if embedding {
		operation = "/internal/model/embed"
		expectedCost = 5000
		expectedOutput = 0
		expectedResult = "vectors"
	}
	if knowledgeCall {
		operation = "/internal/knowledge/search"
	}

	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("PUBLIC_TEST_POSTGRES_MIGRATION_DSN is only set by the isolated Compose E2E")
	}

	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatalf("connect isolated billing Postgres: %v", err)
	}

	governance := modelgovernance.NewSQLStore(db)
	if err = governance.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure governance schema: %v", err)
	}
	usage := usagecost.NewSQLStore(db)
	if err = usage.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure usage/budget schema: %v", err)
	}
	invocations, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = invocations.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure invocation schema: %v", err)
	}
	capacity := modelcapacity.NewSQLProvider(db)
	if err = capacity.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure capacity schema: %v", err)
	}

	providerID := billingIntegrationID(t)
	definitionID := billingIntegrationID(t)
	versionID := billingIntegrationID(t)
	priceID := billingIntegrationID(t)
	deploymentID := billingIntegrationID(t)
	tenantID := "bill-tenant-" + strings.ReplaceAll(providerID[:8], "-", "")
	departmentID := "bill-dept-" + providerID[:8]
	applicationID := "bill-app-" + providerID[:8]
	agentID := "bill-agent-" + providerID[:8]
	agentVersionID := "bill-agent-version-" + providerID[:8]
	providerKey := "budget-provider-" + providerID[:8]
	modelKey := "budget-model-" + definitionID[:8]
	endpointRef := "service://budget-upstream"
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
			if embedding {
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
	price.ContentHash = billingIntegrationPriceHash(t, price)
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

	capContext := capabilityContext()
	capContext.TenantID, capContext.DepartmentID, capContext.ApplicationID = tenantID, departmentID, applicationID
	capContext.AgentID, capContext.AgentVersionID = agentID, agentVersionID
	capContext.TaskID, capContext.SessionID = "bill-run-"+providerID[:8], "bill-session-"+providerID[:8]
	capContext.RequestID, capContext.TraceID = "bill-request-"+providerID[:8], strings.Repeat("b", 32)
	capContext.ActorID = "bill-user-" + providerID[:8]
	invocationScopeHash := capabilityScopeHash(capContext)
	usageScope := usagecost.Scope{
		TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID,
		AgentID: agentID, AgentVersionID: agentVersionID, RunID: runtimeUsageRunID(capContext),
	}
	windowScopeJSON := billingIntegrationScopeJSON(t, usagecost.ModelBudgetScope{
		TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID,
		AgentID: agentID, AgentVersionID: agentVersionID,
	})
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_capacity_lease WHERE deployment_id=?`), deploymentID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_capacity_pool WHERE deployment_id=?`), deploymentID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_budget_settlement WHERE reservation_id IN (SELECT reservation_id FROM platform_model_budget_reservation WHERE tenant_id=? AND agent_id=?)`), tenantID, agentID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_budget_reservation WHERE tenant_id=? AND agent_id=?`), tenantID, agentID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_budget_window WHERE scope_json=?`), windowScopeJSON)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_usage_event WHERE tenant_id=? AND agent_id=?`), tenantID, agentID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_usage_snapshot WHERE scope_key=?`), usagecost.ScopeKey(usageScope))
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_invocation WHERE scope_hash=?`), invocationScopeHash)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_price_version WHERE id=?`), priceID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_version WHERE id=?`), versionID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_definition WHERE id=?`), definitionID)
		_, _ = db.ExecContext(cleanupCtx, sqlutil.Bind(`DELETE FROM platform_model_provider WHERE id=?`), providerID)
	})

	var secretAvailable atomic.Bool
	secretAvailable.Store(false)
	var providerCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		path := "/v1/chat/completions"
		if embedding {
			path = "/v1/embeddings"
		}
		if r.URL.Path != path || r.Header.Get("Authorization") != "Bearer integration-secret" {
			http.Error(w, "invalid guarded model request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if embedding {
			if r.URL.Path != "/v1/embeddings" {
				t.Error("wrong embedding endpoint")
			}
			_, _ = w.Write([]byte(`{"data":[{"index":0,"embedding":[1,0.5]}],"usage":{"prompt_tokens":50,"total_tokens":50}}`))
		} else if functionCall {
			var request struct {
				Tools []struct {
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tools"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Tools) != 1 || request.Tools[0].Function.Name != "inspect" {
				t.Error("published native function definition missing")
			}
			name := "inspect"
			if invalidFunction {
				name = "delete_everything"
			}
			response := map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"content": nil, "tool_calls": []any{map[string]any{"id": "call-1", "type": "function", "function": map[string]any{"name": name, "arguments": "{}"}}}}}}, "usage": map[string]int{"prompt_tokens": 50, "completion_tokens": 20}}
			_ = json.NewEncoder(w).Encode(response)
		} else {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"budget integration answer"}}],"usage":{"prompt_tokens":50,"completion_tokens":20}}`))
		}
	}))
	defer upstream.Close()
	access := modelAccessResolverFunc(func(_ context.Context, scope sharedkernel.Scope, requestedVersion string) (modelgateway.Selection, error) {
		if scope.TenantID != tenantID || scope.ApplicationID != applicationID || requestedVersion != versionID {
			return modelgateway.Selection{}, modelgovernance.ErrModelAccessDenied
		}
		return modelgateway.Selection{
			ModelVersionID: versionID, ProviderID: providerID, ProviderKey: providerKey,
			ModelID: definitionID, ModelKey: modelKey, TrustZone: modelgovernance.TrustLocal,
			DeploymentID: deploymentID, EndpointRef: endpointRef, CapacityUnits: 1,
		}, nil
	})
	secretResolver := billingIntegrationSecretResolver{available: &secretAvailable}
	modelHTTP, err := modelgateway.NewHTTPAdapter(modelgateway.HTTPConfig{
		SecretRoot: t.TempDir(), AllowLoopbackDevelopment: true,
	}, access, governance, governance, secretResolver, modelgateway.StaticEndpointResolver{endpointRef: upstream.URL + "/v1"})
	if err != nil {
		t.Fatalf("create guarded HTTP Model Gateway: %v", err)
	}
	policy := governedInvocationResolver()
	policy.snapshot.Model.Provider = providerKey
	policy.snapshot.Model.Model = modelKey
	policy.snapshot.Model.ModelVersionID = versionID
	policy.snapshot.Model.BudgetCents = 1
	if functionCall {
		policy.snapshot.Model.BudgetCents = 5
		policy.snapshot.Tool = policyasset.ToolPolicy{AllowedTools: []string{"runtime.inspect"}, Functions: []policyasset.FunctionDefinition{{Name: "inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)}}}
	}
	if embedding {
		policy.snapshot.Model.EmbeddingModelVersionID = versionID
		policy.snapshot.Model.EmbeddingProvider = providerKey
		policy.snapshot.Model.EmbeddingModel = modelKey
		// The primary target is deliberately not resolvable by this fixture. SQL
		// governance and billing must use the published embedding version instead.
		policy.snapshot.Model.ModelVersionID = "separate-chat-version"
		policy.snapshot.Model.Provider = "separate-chat-provider"
		policy.snapshot.Model.Model = "separate-chat-model"
	}
	module := NewModuleWithGovernance("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, policy, nil, invocations)
	module.SetGovernedModelInvocation(access, modelHTTP)
	module.SetModelBilling(governance, usage)
	module.SetModelCapacity(capacity)
	var retained KnowledgeModelCall
	if knowledgeCall {
		// This fixture isolates callback billing. Legacy document authority is
		// explicit; production v2 source/IAM integration is verified separately.
		module.knowledge = knowledgeProviderFunc(func(ctx context.Context, _ harnessContext, q knowledgeQuery) (map[string]any, error) {
			retained = q.ModelCall
			if q.ModelCall == nil {
				return nil, ErrKnowledgePortUnavailable
			}
			if _, err := q.ModelCall(ctx, "tool", map[string]any{}); err == nil {
				t.Fatal("knowledge callback reached non-model capability")
			}
			return q.ModelCall(ctx, "embed", map[string]any{"texts": []string{q.Query}, "idempotency_key": "forged-global-key"})
		})
	}

	input := map[string]any{
		"idempotency_key": "billing-success-" + providerID[:8], "prompt_template_hash": "prompt-hash",
		"max_tokens": 20, "messages": []map[string]string{{"role": "user", "content": "hello"}},
	}
	if functionCall {
		input["function_names"] = []string{"inspect"}
	}
	if embedding {
		input = map[string]any{"idempotency_key": "billing-success-" + providerID[:8], "texts": []string{"hello"}, "model_version_id": "unapproved-request-override", "provider": "unapproved-provider"}
	}
	if knowledgeCall {
		input = map[string]any{"query": "hello", "knowledge_scope": "platform-knowledge", "top_k": 1}
	}
	failed := capabilityRequest(t, module, operation, capContext, input)
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "MODEL_PROVIDER_FAILED") || providerCalls.Load() != 0 {
		t.Fatalf("secret lookup failure must stop before provider and release billing: status=%d provider_calls=%d body=%s", failed.Code, providerCalls.Load(), failed.Body.String())
	}
	secretAvailable.Store(true)
	completed := capabilityRequest(t, module, operation, capContext, input)
	if completed.Code != expectedStatus || providerCalls.Load() != 1 || !strings.Contains(completed.Body.String(), expectedResult) || !invalidFunction && !strings.Contains(completed.Body.String(), fmt.Sprintf(`"cost_micros":%d`, expectedCost)) {
		t.Fatalf("approved-price model call did not settle the actual provider usage: status=%d provider_calls=%d body=%s", completed.Code, providerCalls.Load(), completed.Body.String())
	}
	var expectedStepID *string
	if requestID, ok := input["idempotency_key"].(string); ok {
		expectedStepID = usagecost.StableModelUsageStepID(usageScope, requestID)
		if expectedStepID == nil || !strings.Contains(completed.Body.String(), fmt.Sprintf(`"step_id":"%s"`, *expectedStepID)) {
			t.Fatalf("model response must carry the same stable usage step ID: expected=%v body=%s", expectedStepID, completed.Body.String())
		}
	}
	replay := capabilityRequest(t, module, operation, capContext, input)
	var completedJSON, replayJSON any
	_ = json.Unmarshal(completed.Body.Bytes(), &completedJSON)
	_ = json.Unmarshal(replay.Body.Bytes(), &replayJSON)
	if replay.Code != expectedStatus || !reflect.DeepEqual(completedJSON, replayJSON) || providerCalls.Load() != 1 {
		t.Fatalf("completed idempotent request must replay without a second provider charge: replay_status=%d provider_calls=%d", replay.Code, providerCalls.Load())
	}
	if !embedding && !knowledgeCall {
		runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
		if runtimeDSN == "" {
			t.Fatal("DML receipt reader required")
		}
		readerDB, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
		if err != nil {
			t.Fatal(err)
		}
		defer readerDB.Close()
		reader, err := NewSQLModelInvocationStore(readerDB)
		if err != nil {
			t.Fatal(err)
		}
		module.modelStore = reader
		var before, after time.Time
		if err := db.QueryRowContext(ctx, `SELECT updated_at FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2`, capabilityScopeHash(capContext), input["idempotency_key"]).Scan(&before); err != nil {
			t.Fatal(err)
		}
		read := capabilityRequest(t, module, "/internal/model/receipt", capContext, input)
		if read.Code != 200 || !strings.Contains(read.Body.String(), `"version":"model-receipt/v1"`) || !strings.Contains(read.Body.String(), `"status":"completed"`) || providerCalls.Load() != 1 {
			t.Fatal("receipt read executed or failed", read.Code)
		}
		if expectedStepID != nil && !strings.Contains(read.Body.String(), fmt.Sprintf(`"step_id":"%s"`, *expectedStepID)) {
			t.Fatal("completed model receipt did not preserve its usage step ID", read.Body.String())
		}
		if err := db.QueryRowContext(ctx, `SELECT updated_at FROM platform_model_invocation WHERE scope_hash=$1 AND idempotency_key=$2`, capabilityScopeHash(capContext), input["idempotency_key"]).Scan(&after); err != nil || !after.Equal(before) {
			t.Fatal("receipt lookup updated ledger", err)
		}
	}

	secondInput := map[string]any{
		"idempotency_key": "billing-over-limit-" + providerID[:8], "prompt_template_hash": "prompt-hash",
		"max_tokens": 20, "messages": []map[string]string{{"role": "user", "content": "hello"}},
	}
	if functionCall {
		secondInput["function_names"] = []string{"inspect"}
		secondInput["messages"] = []map[string]string{{"role": "user", "content": strings.Repeat("hello ", 2000)}}
	}
	if embedding {
		secondInput = map[string]any{"idempotency_key": "billing-over-limit-" + providerID[:8], "texts": []string{strings.Repeat("hello ", 10)}}
	}
	if knowledgeCall {
		secondInput = map[string]any{"query": strings.Repeat("hello ", 10), "knowledge_scope": "platform-knowledge", "top_k": 1}
	}
	overLimit := capabilityRequest(t, module, operation, capContext, secondInput)
	if overLimit.Code != http.StatusPaymentRequired || !strings.Contains(overLimit.Body.String(), "MODEL_BUDGET_EXCEEDED") || providerCalls.Load() != 1 {
		t.Fatalf("budget must reject before a second provider call: status=%d provider_calls=%d body=%s", overLimit.Code, providerCalls.Load(), overLimit.Body.String())
	}

	snapshot, err := usage.GetSnapshot(ctx, usageScope)
	if err != nil || snapshot.UsedMicros != expectedCost || snapshot.InputTokens != 50 || snapshot.OutputTokens != expectedOutput {
		t.Fatalf("usage event did not persist actual provider token counts/cost: snapshot=%+v err=%v", snapshot, err)
	}
	if expectedStepID != nil {
		var storedStepID sql.NullString
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT step_id FROM platform_usage_event WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_id=? AND agent_version_id=? AND run_id=? ORDER BY created_at DESC,event_id DESC LIMIT 1`), usageScope.TenantID, usageScope.DepartmentID, usageScope.ApplicationID, usageScope.AgentID, usageScope.AgentVersionID, usageScope.RunID).Scan(&storedStepID); err != nil || !storedStepID.Valid || storedStepID.String != *expectedStepID {
			t.Fatalf("settled SQL usage row must match model response step ID: value=%+v err=%v", storedStepID, err)
		}
	}
	var actualMicros, reservedMicros int64
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT actual_micros,reserved_micros FROM platform_model_budget_window WHERE scope_json=?`), windowScopeJSON).Scan(&actualMicros, &reservedMicros); err != nil {
		t.Fatalf("read SQL budget window: %v", err)
	}
	if actualMicros != expectedCost || reservedMicros != 0 {
		t.Fatalf("settled budget window mismatch: actual=%d reserved=%d", actualMicros, reservedMicros)
	}
	var released, settled int
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FILTER (WHERE status='released'),COUNT(*) FILTER (WHERE status='settled') FROM platform_model_budget_reservation WHERE tenant_id=? AND agent_id=?`), tenantID, agentID).Scan(&released, &settled); err != nil {
		t.Fatalf("read SQL budget reservations: %v", err)
	}
	if released != 1 || settled != 1 {
		t.Fatalf("failed attempt must release and successful attempt must settle: released=%d settled=%d", released, settled)
	}
	var capacityReserved int64
	if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT reserved_units FROM platform_model_capacity_pool WHERE deployment_id=?`), deploymentID).Scan(&capacityReserved); err != nil {
		t.Fatalf("read SQL model capacity pool: %v", err)
	}
	if capacityReserved != 0 {
		t.Fatalf("capacity lease leaked after completed/definite failure calls: reserved_units=%d", capacityReserved)
	}
	if knowledgeCall {
		if _, err := retained(context.Background(), "embed", map[string]any{"texts": []string{"retained"}}); !errors.Is(err, context.Canceled) || providerCalls.Load() != 1 {
			t.Fatal("retained callback continued after knowledge request lifetime", err)
		}
	}
}

type billingIntegrationSecretResolver struct{ available *atomic.Bool }

func (r billingIntegrationSecretResolver) ResolveSecret(_ context.Context, reference string) ([]byte, error) {
	if !r.available.Load() || !strings.HasPrefix(reference, "secret://billing/") {
		return nil, errors.New("test secret is unavailable")
	}
	return []byte("integration-secret"), nil
}

func billingIntegrationID(t *testing.T) string {
	t.Helper()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func billingIntegrationPriceHash(t *testing.T, price modelgovernance.PriceVersion) string {
	t.Helper()
	payload := struct {
		ModelVersionID    string     `json:"model_version_id"`
		Currency          string     `json:"currency"`
		InputMicrosPer1K  int64      `json:"input_micros_per_1k_tokens"`
		OutputMicrosPer1K int64      `json:"output_micros_per_1k_tokens"`
		EffectiveFrom     time.Time  `json:"effective_from"`
		EffectiveUntil    *time.Time `json:"effective_until,omitempty"`
	}{price.ModelVersionID, price.Currency, price.InputMicrosPer1K, price.OutputMicrosPer1K, price.EffectiveFrom.UTC(), price.EffectiveUntil}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func billingIntegrationScopeJSON(t *testing.T, scope usagecost.ModelBudgetScope) string {
	t.Helper()
	canonical := struct {
		TenantID       string `json:"tenant_id"`
		DepartmentID   string `json:"department_id"`
		ApplicationID  string `json:"application_id"`
		AgentID        string `json:"agent_id"`
		AgentVersionID string `json:"agent_version_id"`
	}{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentID, scope.AgentVersionID}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

var _ policyasset.Resolver = fixedPolicyResolver{}
