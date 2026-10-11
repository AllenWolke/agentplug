package catalog

import (
	"encoding/json"
	"testing"
)

func definition() Definition {
	return Definition{ID: "definition", PublisherID: "publisher", AgentKey: "example-agent", DisplayName: "Validation", Description: "Validates versioned business input.", Status: DefinitionPublished, Revision: 2}
}

func version() Version {
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"example-agent","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://validation/input/v1","output":"schema://validation/output/v1","event":"schema://validation/event/v1","checkpoint":"schema://validation/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	input := json.RawMessage(`{"type":"object","properties":{"batch_id":{"type":"string"}}}`)
	output := json.RawMessage(`{"type":"object","properties":{"status":{"type":"string"}}}`)
	hash, _ := VersionContentHash(manifest, input, output)
	return Version{ID: "version", DefinitionID: "definition", SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InputSchema: input, OutputSchema: output, Status: DefinitionPublished, Revision: 3}
}

func TestVersionSnapshotIsStable(t *testing.T) {
	snapshot, err := version().Snapshot(definition())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AgentID != "example-agent" || snapshot.VersionID != "version" || snapshot.ManifestHash == "" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestVersionSnapshotRejectsWrongDefinition(t *testing.T) {
	wrong := definition()
	wrong.ID = "other"
	if _, err := version().Snapshot(wrong); err != ErrInvalidVersion {
		t.Fatalf("expected invalid version, got %v", err)
	}
}

func TestInstallationTransitionAndRevisionFence(t *testing.T) {
	if err := ValidateInstallationTransition(InstallationProvisioning, InstallationActive); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstallationTransition(InstallationActive, InstallationUninstalled); err != ErrIllegalTransition {
		t.Fatalf("expected illegal transition, got %v", err)
	}
	installation := Installation{ID: "i", TenantID: "tenant-a", DepartmentID: "d", ApplicationID: "app", AgentID: "validation", VersionID: "v1", DisplayName: "Validation Agent", DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "default", Status: InstallationActive, Revision: 2}
	if installation.Revision != 2 || installation.TenantID != "tenant-a" {
		t.Fatal("installation lost scoped revision identity")
	}
}

func TestCatalogRejectsUnknownStatusesAndNonDigestArtifacts(t *testing.T) {
	invalidDefinition := definition()
	invalidDefinition.Status = "released-by-client"
	if err := invalidDefinition.Validate(); err != ErrInvalidDefinition {
		t.Fatalf("unknown definition status must be rejected: %v", err)
	}
	invalidVersion := version()
	invalidVersion.ArtifactDigest = "artifact-without-digest"
	if err := invalidVersion.Validate(); err != ErrInvalidVersion {
		t.Fatalf("non-digest artifact must be rejected: %v", err)
	}
	invalidInstallation := Installation{ID: "i", TenantID: "t", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", VersionID: "v", DisplayName: "Agent", DeploymentMode: "managed", DrainPolicy: "wait", RetentionPolicyID: "default", Status: "active-ish", Revision: 1}
	if err := invalidInstallation.Validate(); err != ErrInvalidInstallation {
		t.Fatalf("unknown installation status must be rejected: %v", err)
	}
}
