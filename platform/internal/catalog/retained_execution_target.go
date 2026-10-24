package catalog

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// ResolveRetainedExecutionTarget is an internal continuation port. Its caller
// must prove an existing Run's exact persisted scope/endpoint and current
// workload retention. New executions keep using ResolveEvaluationAgentTarget.
// No endpoint, artifact or policy is selected from browser input or 'latest'.
func (m *Module) ResolveRetainedExecutionTarget(ctx context.Context, scope sharedkernel.Scope, endpoint string) (EvaluationAgentTarget, error) {
	if m == nil || m.store == nil || scope.ValidateTrusted() != nil || endpoint == "" {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	installation, err := m.store.GetInstallation(ctx, scope.InstallationID)
	if err != nil || installation.ID != scope.InstallationID || scope.AgentInstanceID != installation.ID || installation.TenantID != scope.TenantID || installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID || installation.AgentID != scope.AgentID || installation.Status != InstallationActive {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	current, err := m.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, installation.VersionID)
	if err != nil {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	if installation.VersionID == scope.AgentVersionID {
		if current.Endpoint != endpoint {
			return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
		}
		return current, nil
	}
	version, manifest, err := m.publishedExecutionVersion(ctx, scope.AgentID, scope.AgentVersionID)
	if err != nil {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	selected, _, err := m.publishedExecutionVersion(ctx, scope.AgentID, installation.VersionID)
	if err != nil || selected.DefinitionID != version.DefinitionID {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	deployments, err := m.store.ListDeployments(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.InstallationID, 100)
	if err != nil {
		return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
	}
	// The first deployment of the pinned version is authoritative. A newer
	// failed/pending deployment cannot fall back to an older ready container.
	for _, deployment := range deployments {
		if deployment.AgentVersionID != scope.AgentVersionID {
			continue
		}
		if deployment.TenantID != scope.TenantID || deployment.DepartmentID != scope.DepartmentID || deployment.ApplicationID != scope.ApplicationID || deployment.AgentInstallationID != scope.InstallationID || deployment.EndpointRef != endpoint || deployment.Status != DeploymentReady || deployment.DesiredRevision == 0 || deployment.ObservedRevision != deployment.DesiredRevision || deployment.ManifestHash != version.ManifestHash || deployment.ArtifactDigest != version.ArtifactDigest || !validDeploymentEndpoint(endpoint, deployment.Transport) {
			return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
		}
		return EvaluationAgentTarget{AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, InstallationID: scope.InstallationID, InputSchemaURI: manifest.Schemas.Input, Endpoint: endpoint, Transport: deployment.Transport, Revision: installation.Revision, ManifestHash: version.ManifestHash}, nil
	}
	return EvaluationAgentTarget{}, ErrEvaluationTargetUnavailable
}
