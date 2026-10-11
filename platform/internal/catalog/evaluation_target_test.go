package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func evaluationCatalogFixture(t *testing.T) (*Module, *memoryStore) {
	t.Helper()
	const agentID = "eval-agent"
	const versionID = "eval-version-1"
	inputSchema := json.RawMessage(`{"type":"object"}`)
	outputSchema := json.RawMessage(`{"type":"object"}`)
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"eval-agent","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["evaluate"],"schemas":{"input":"schema://eval-agent/input/v1","output":"schema://eval-agent/output/v1","event":"schema://eval-agent/event/v1","checkpoint":"schema://eval-agent/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health"}}`)
	hash, err := VersionContentHash(manifest, inputSchema, outputSchema)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("agent artifact"))
	artifactDigest := "sha256:" + hex.EncodeToString(digest[:])
	definition := Definition{ID: "eval-definition", PublisherID: "publisher", AgentKey: agentID, DisplayName: "Eval", Description: "Eval agent", Status: DefinitionPublished, Revision: 1}
	version := Version{ID: versionID, DefinitionID: definition.ID, SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: artifactDigest, InputSchema: inputSchema, OutputSchema: outputSchema, Status: DefinitionPublished, Revision: 1}
	installation := Installation{ID: "eval-installation", TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentID: agentID, VersionID: versionID, Status: InstallationActive, Revision: 8}
	deployment := Deployment{ID: "deployment-1", TenantID: installation.TenantID, DepartmentID: installation.DepartmentID, ApplicationID: installation.ApplicationID, AgentVersionID: versionID, AgentInstallationID: installation.ID, ArtifactDigest: artifactDigest, Transport: "http", EndpointRef: "http://catalog-agent:8080", Status: DeploymentReady, DesiredRevision: 4, ObservedRevision: 4, ManifestHash: hash}
	store := &memoryStore{definition: definition, version: version, installations: []Installation{installation}, deployments: []Deployment{deployment}}
	return NewModule(store, "internal"), store
}

func TestResolveEvaluationAgentTargetPinsExactReadyCatalogBinding(t *testing.T) {
	module, _ := evaluationCatalogFixture(t)
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", PrincipalID: "alice"}
	target, err := module.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1")
	if err != nil {
		t.Fatalf("resolve evaluation target: %v", err)
	}
	if target.InstallationID != "eval-installation" || target.AgentVersionID != "eval-version-1" || target.InputSchemaURI != "schema://eval-agent/input/v1" || target.Endpoint != "http://catalog-agent:8080" || target.Revision != 8 {
		t.Fatalf("target did not preserve exact catalog binding: %+v", target)
	}
}

func TestResolveEvaluationAgentTargetRejectsCrossScopeVersionAndLatestDeploymentMismatch(t *testing.T) {
	module, store := evaluationCatalogFixture(t)
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", PrincipalID: "alice"}
	crossScope := scope
	crossScope.ApplicationID = "application-b"
	if _, err := module.ResolveEvaluationAgentTarget(context.Background(), crossScope, "eval-agent", "eval-version-1"); err == nil {
		t.Fatal("cross-application installation resolved")
	}
	if _, err := module.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "another-version"); err == nil {
		t.Fatal("suite version mismatch resolved")
	}
	store.deployments = append(store.deployments, Deployment{ID: "deployment-2", TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", AgentVersionID: "eval-version-1", AgentInstallationID: "eval-installation", ArtifactDigest: store.version.ArtifactDigest, Transport: "http", EndpointRef: "http://new-agent:8080", Status: DeploymentPending, DesiredRevision: 5, ObservedRevision: 4, ManifestHash: store.version.ManifestHash})
	if _, err := module.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1"); err == nil {
		t.Fatal("resolver fell back to an older ready deployment")
	}
}

func TestResolveEvaluationAgentTargetRejectsAmbiguousAndUntrustedInstallation(t *testing.T) {
	module, store := evaluationCatalogFixture(t)
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", PrincipalID: "alice"}
	store.installations = append(store.installations, store.installations[0])
	if _, err := module.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1"); err == nil {
		t.Fatal("ambiguous installation resolved")
	}
	store.installations = store.installations[:1]
	store.installations[0].Status = InstallationSuspended
	if _, err := module.ResolveEvaluationAgentTarget(context.Background(), scope, "eval-agent", "eval-version-1"); err == nil {
		t.Fatal("suspended installation resolved")
	}
}
