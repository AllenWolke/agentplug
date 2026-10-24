package catalog

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type retainedCatalogFixture struct {
	*memoryStore
	released map[string]Version
}

func (s *retainedCatalogFixture) GetInstallation(_ context.Context, id string) (Installation, error) {
	for _, item := range s.installations {
		if item.ID == id {
			return item, nil
		}
	}
	return Installation{}, ErrInstallationNotFound
}

func (s *retainedCatalogFixture) GetVersion(_ context.Context, id string) (Version, error) {
	v, ok := s.released[id]
	if !ok {
		return Version{}, ErrVersionNotFound
	}
	return v, nil
}

func retainedFixture(t *testing.T) (*Module, *retainedCatalogFixture, sharedkernel.Scope) {
	_, old := evaluationCatalogFixture(t)
	next := old.version
	next.ID, next.SemanticVersion = "eval-version-2", "2.0.0"
	var manifest map[string]any
	if err := json.Unmarshal(next.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["version"] = next.SemanticVersion
	next.Manifest, _ = json.Marshal(manifest)
	next.ManifestHash, _ = VersionContentHash(next.Manifest, next.InputSchema, next.OutputSchema)
	old.installations[0].VersionID = next.ID
	d := old.deployments[0]
	d.ID, d.AgentVersionID, d.ManifestHash, d.EndpointRef = "deployment-2", next.ID, next.ManifestHash, "http://current-agent:8080"
	d.DesiredRevision, d.ObservedRevision = 5, 5
	old.deployments = append(old.deployments, d)
	s := &retainedCatalogFixture{memoryStore: old, released: map[string]Version{old.version.ID: old.version, next.ID: next}}
	scope := sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "department-a", ApplicationID: "application-a", PrincipalType: "user", PrincipalID: "alice", AgentID: "eval-agent", AgentInstanceID: "eval-installation", InstallationID: "eval-installation", AgentVersionID: "eval-version-1", RunID: "old-run", SessionID: "old-session", TraceID: "0123456789abcdef0123456789abcdef", AuthorizationEpoch: 2}
	return NewModule(s, "internal"), s, scope
}

func TestRetainedTargetPreservesPinnedVersionAndDoesNotAdmitNewOldVersionRun(t *testing.T) {
	m, _, scope := retainedFixture(t)
	if _, err := m.ResolveEvaluationAgentTarget(context.Background(), scope, scope.AgentID, scope.AgentVersionID); err == nil {
		t.Fatal("new old-version execution admitted")
	}
	target, err := m.ResolveRetainedExecutionTarget(context.Background(), scope, "http://catalog-agent:8080")
	if err != nil || target.AgentVersionID != scope.AgentVersionID || target.Endpoint != "http://catalog-agent:8080" {
		t.Fatalf("pinned target unavailable: %+v %v", target, err)
	}
}

func TestRetainedTargetRejectsForeignScopeEndpointPublicationAndDeploymentDrift(t *testing.T) {
	for _, variant := range []string{"foreign", "instance", "endpoint", "unpublished", "definition", "suspended", "current pending", "old artifact", "old pending"} {
		t.Run(variant, func(t *testing.T) {
			m, s, scope := retainedFixture(t)
			endpoint := "http://catalog-agent:8080"
			switch variant {
			case "foreign":
				scope.ApplicationID = "another-app"
			case "instance":
				scope.AgentInstanceID = "other-installation"
			case "endpoint":
				endpoint = "http://attacker:8080"
			case "unpublished":
				v := s.released[scope.AgentVersionID]
				v.Status = DefinitionDraft
				s.released[v.ID] = v
			case "definition":
				v := s.released[scope.AgentVersionID]
				v.DefinitionID = "foreign-definition"
				s.released[v.ID] = v
			case "suspended":
				s.installations[0].Status = InstallationSuspended
			case "current pending":
				s.deployments[1].Status = DeploymentPending
			case "old artifact":
				s.deployments[0].ArtifactDigest = "sha256:wrong"
			case "old pending":
				d := s.deployments[0]
				d.ID, d.Status, d.DesiredRevision = "old-replacement", DeploymentPending, 6
				s.deployments = append(s.deployments, d)
			}
			if _, err := m.ResolveRetainedExecutionTarget(context.Background(), scope, endpoint); err == nil {
				t.Fatal("invalid retained target admitted")
			}
		})
	}
}
