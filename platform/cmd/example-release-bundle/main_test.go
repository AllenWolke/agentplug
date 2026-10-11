package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/policyasset"
)

func TestGoExampleProducesActualCatalogRequestBodies(t *testing.T) {
	o := options{directory: filepath.Join("..", "..", "..", "examples", "go-operations"), digest: "sha256:" + strings.Repeat("a", 64), publisher: "system.admin", tenant: "tenant-demo", department: "dept-demo", application: "app-demo", endpoint: "http://example-go:8080"}
	b, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Requests) != 9 || !strings.HasPrefix(b.ManifestHash, "sha256:") {
		t.Fatal("missing release steps or canonical content hash")
	}
	for _, request := range b.Requests {
		if _, err := json.Marshal(request.Body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(request.Path, "observe") {
			t.Fatal("bundle must not fabricate deployment readiness")
		}
	}
	version := b.Requests[1].Body.(map[string]any)
	if _, exists := version["manifest_hash"]; exists {
		t.Fatal("strict Catalog POST does not accept manifest_hash")
	}
	if version["definition_id"] != "example-go-operations-definition" || b.Requests[4].Stage != "approve" {
		t.Fatal("release provenance or approval boundary missing")
	}
	deployment := b.Requests[7].Body.(map[string]any)
	if deployment["status"] != "pending" || deployment["manifest_hash"] != b.ManifestHash {
		t.Fatal("deployment must pin canonical content and await readiness")
	}
}

func TestReleaseBundleRejectsUnbuiltArtifactsAndUnsafeIdentifiers(t *testing.T) {
	o := options{directory: filepath.Join("..", "..", "..", "examples", "go-operations"), digest: "agentplug:example-go", publisher: "system.admin", tenant: "tenant-demo", department: "dept-demo", application: "app-demo", endpoint: "http://example-go:8080"}
	if _, err := prepare(o); err == nil {
		t.Fatal("image tag accepted as immutable artifact digest")
	}
	o.digest = "sha256:" + strings.Repeat("a", 64)
	o.application = "other/app"
	if _, err := prepare(o); err == nil {
		t.Fatal("path-injecting scope accepted")
	}
}

func policyInputForTest(t *testing.T, installationID, versionID string) []byte {
	t.Helper()
	input := policyInput{
		InstallationID: installationID,
		Scope:          policyasset.Scope{TenantID: "tenant-demo", DepartmentID: "dept-demo", ApplicationID: "app-demo", AgentID: "example-go-operations", AgentVersionID: versionID},
		Assets: []policyInputAsset{
			{ID: "example-model-v2", Type: policyasset.AssetModel, Content: json.RawMessage(`{"provider":"local","model":"m","max_tokens":128,"temperature":0,"allow_external":false,"budget_cents":10,"input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":0}`)},
			{ID: "example-prompt-v2", Type: policyasset.AssetPrompt, Content: json.RawMessage(`{"template_hash":"prompt-v2","template":"Use the approved example prompt."}`)},
			{ID: "example-tool-v2", Type: policyasset.AssetTool, Content: json.RawMessage(`{"allowed_tools":["runtime.inspect"],"require_confirmation":[],"functions":[]}`)},
			{ID: "example-memory-v2", Type: policyasset.AssetMemory, Content: json.RawMessage(`{"working_ttl_seconds":60,"session_ttl_seconds":120,"task_ttl_seconds":30,"max_entries":20,"long_term_enabled":false,"semantic_enabled":false}`)},
			{ID: "example-knowledge-v2", Type: policyasset.AssetKnowledge, Content: json.RawMessage(`{"allowed_scopes":["example-knowledge"],"require_references":true,"allow_partial_degraded":false,"allow_replay":false}`)},
			{ID: "example-runtime-v2", Type: policyasset.AssetRuntime, Content: json.RawMessage(`{"max_attempts":2,"task_timeout_seconds":30,"lease_seconds":60,"cancel_grace_seconds":5,"run_budget":{"limit_tokens":1000,"limit_micros":2500}}`)},
		},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOptionalPolicyPreparationPreservesExplicitRuntimeBudgetAndLeavesCASBlank(t *testing.T) {
	directory := filepath.Join("..", "..", "..", "examples", "go-operations")
	o := options{directory: directory, digest: "sha256:" + strings.Repeat("a", 64), publisher: "system.admin", tenant: "tenant-demo", department: "dept-demo", application: "app-demo", endpoint: "http://example-go:8080"}
	base, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	versionID := base.Requests[1].Body.(map[string]any)["id"].(string)
	installationID := base.Requests[6].Body.(catalog.Installation).ID
	path := filepath.Join(t.TempDir(), "policies.json")
	if err := os.WriteFile(path, policyInputForTest(t, installationID, versionID), 0600); err != nil {
		t.Fatal(err)
	}
	o.policyInput = path
	result, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicyPublication == nil || result.PolicyPublication.ReadyToSubmit || result.PolicyPublication.SnapshotReadyToSubmit || len(result.PolicyPublication.Assets) != 6 {
		t.Fatal("policy preparation must be complete for review but not marked ready to submit")
	}
	for _, asset := range result.PolicyPublication.Assets {
		if _, ok := asset.PublishRequest.Body.(map[string]any)["expected_revision"]; ok {
			t.Fatal("asset CAS must be read live, never guessed")
		}
	}
	snapshotBody := result.PolicyPublication.PublishSnapshotRequest.Body.(map[string]any)
	if _, ok := snapshotBody["expected_revision"]; ok {
		t.Fatal("snapshot CAS must be read live, never guessed")
	}
	assets := snapshotBody["assets"].(map[policyasset.AssetType]map[string]any)
	if _, ok := assets[policyasset.AssetRuntime]["revision"]; ok {
		t.Fatal("snapshot asset revisions must be read live, never guessed")
	}
	var runtime policyasset.RuntimePolicy
	for _, asset := range result.PolicyPublication.Assets {
		if asset.Type != string(policyasset.AssetRuntime) {
			continue
		}
		content := asset.CreateRequest.Body.(map[string]any)["content"].(json.RawMessage)
		if err := json.Unmarshal(content, &runtime); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.RunBudget == nil || runtime.RunBudget.LimitTokens != 1000 || runtime.RunBudget.LimitMicros != 2500 {
		t.Fatal("explicit runtime budget was not preserved")
	}
}

func TestOptionalPolicyPreparationRejectsCredentialsAndFunctionConflicts(t *testing.T) {
	directory := filepath.Join("..", "..", "..", "examples", "go-operations")
	o := options{directory: directory, digest: "sha256:" + strings.Repeat("a", 64), publisher: "system.admin", tenant: "tenant-demo", department: "dept-demo", application: "app-demo", endpoint: "http://example-go:8080"}
	base, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	versionID := base.Requests[1].Body.(map[string]any)["id"].(string)
	installationID := base.Requests[6].Body.(catalog.Installation).ID
	valid := policyInputForTest(t, installationID, versionID)
	var withCredential map[string]json.RawMessage
	if err := json.Unmarshal(valid, &withCredential); err != nil {
		t.Fatal(err)
	}
	withCredential["operator_password"] = json.RawMessage(`"must be rejected"`)
	credentialInput, _ := json.Marshal(withCredential)
	path := filepath.Join(t.TempDir(), "policies.json")
	if err := os.WriteFile(path, credentialInput, 0600); err != nil {
		t.Fatal(err)
	}
	o.policyInput = path
	if _, err := prepare(o); err == nil {
		t.Fatal("unknown credential field was accepted")
	}

	var input policyInput
	if err := json.Unmarshal(valid, &input); err != nil {
		t.Fatal(err)
	}
	input.Assets[2].Content = json.RawMessage(`{"allowed_tools":["runtime.inspect"],"require_confirmation":[],"functions":[{"name":"inspect","tool_name":"runtime.inspect","description":"conflicting definition","parameters":{"type":"object","properties":{},"additionalProperties":false}}]}`)
	conflictInput, _ := json.Marshal(input)
	if err := os.WriteFile(path, conflictInput, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(o); err == nil {
		t.Fatal("conflicting function definition was accepted")
	}
}
