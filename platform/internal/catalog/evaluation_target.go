package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrEvaluationTargetUnavailable = errors.New("evaluation agent target unavailable")

// EvaluationAgentTarget is the catalog-owned runtime binding for one frozen
// evaluation suite. Endpoint data is returned only after resolving an exact
// scoped installation, published version and latest ready deployment.
type EvaluationAgentTarget struct {
	AgentID        string
	AgentVersionID string
	InstallationID string
	InputSchemaURI string
	Endpoint       string
	Transport      string
	Revision       uint64
	ManifestHash   string
}

// ResolveEvaluationAgentTarget binds a suite's Agent/version to exactly one
// active installation in the full application scope. The latest desired
// deployment must be observed ready; an older ready deployment is never used
// as a fallback during rollout.
func (m *Module) ResolveEvaluationAgentTarget(ctx context.Context, scope sharedkernel.Scope, agentID, versionID string) (EvaluationAgentTarget, error) {
	if m == nil || m.store == nil || scope.Validate() != nil ||
		strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(scope.DepartmentID) == "" || strings.TrimSpace(scope.ApplicationID) == "" ||
		strings.TrimSpace(agentID) == "" || strings.TrimSpace(versionID) == "" {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	reader, ok := m.store.(CatalogListReader)
	if !ok {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	var installations []Installation
	var err error
	if scope.InstallationID != "" {
		var exact Installation
		exact, err = m.store.GetInstallation(ctx, scope.InstallationID)
		installations = []Installation{exact}
	} else {
		installations, err = reader.ListInstallations(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, 100)
	}
	if err != nil {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	var selected *Installation
	for i := range installations {
		item := &installations[i]
		if item.TenantID != scope.TenantID || item.DepartmentID != scope.DepartmentID || item.ApplicationID != scope.ApplicationID {
			return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
		}
		if item.AgentID != agentID {
			continue
		}
		if selected != nil {
			return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
		}
		selected = item
	}
	if selected == nil || selected.Status != InstallationActive || selected.VersionID != versionID || selected.Revision == 0 {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	version, manifest, err := m.publishedExecutionVersion(ctx, agentID, versionID)
	if err != nil {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	deployments, err := m.store.ListDeployments(ctx, selected.TenantID, selected.DepartmentID, selected.ApplicationID, selected.ID, 1)
	if err != nil || len(deployments) != 1 {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	deployment := deployments[0]
	if deployment.TenantID != selected.TenantID || deployment.DepartmentID != selected.DepartmentID || deployment.ApplicationID != selected.ApplicationID ||
		deployment.AgentInstallationID != selected.ID || deployment.AgentVersionID != versionID || deployment.Status != DeploymentReady ||
		deployment.DesiredRevision == 0 || deployment.ObservedRevision != deployment.DesiredRevision ||
		deployment.ManifestHash != version.ManifestHash || deployment.ArtifactDigest != version.ArtifactDigest || !validDeploymentEndpoint(deployment.EndpointRef, deployment.Transport) {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	return EvaluationAgentTarget{
		AgentID: agentID, AgentVersionID: versionID, InstallationID: selected.ID,
		InputSchemaURI: manifest.Schemas.Input, Endpoint: deployment.EndpointRef,
		Transport: deployment.Transport, Revision: selected.Revision, ManifestHash: version.ManifestHash,
	}, nil
}

func (m *Module) publishedExecutionVersion(ctx context.Context, agentID, versionID string) (Version, agentManifest, error) {
	var manifest agentManifest
	version, err := m.store.GetVersion(ctx, versionID)
	if err != nil || version.ID != versionID || version.Status != DefinitionPublished || version.Validate() != nil {
		return Version{}, manifest, ErrEvaluationTargetUnavailable
	}
	definition, err := m.store.GetDefinition(ctx, version.DefinitionID)
	if err != nil || definition.ID != version.DefinitionID || definition.Status != DefinitionPublished || definition.Validate() != nil || definition.AgentKey != agentID {
		return Version{}, manifest, ErrEvaluationTargetUnavailable
	}
	snapshot, err := version.Snapshot(definition)
	if err != nil || snapshot.AgentID != agentID || snapshot.VersionID != versionID || jsonUnmarshalStrict(version.Manifest, &manifest) != nil || manifest.AgentID != agentID || manifest.Version != version.SemanticVersion || !schemaRef(manifest.Schemas.Input) {
		return Version{}, manifest, ErrEvaluationTargetUnavailable
	}
	return version, manifest, nil
}

// jsonUnmarshalStrict rejects malformed or trailing manifest data while
// keeping the catalog's runtime target resolver independent of generic JSON
// decoding behavior.
func jsonUnmarshalStrict(raw []byte, target any) error {
	if len(raw) == 0 || !json.Valid(raw) {
		return errors.New("invalid manifest JSON")
	}
	return json.Unmarshal(raw, target)
}
