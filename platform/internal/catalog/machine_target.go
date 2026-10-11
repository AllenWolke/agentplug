package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrMachineTargetUnavailable = errors.New("machine agent target unavailable")

// MachineAgentTarget is the trusted execution address resolved from Catalog.
// Public machine callers never provide Agent IDs, versions, or endpoints.
// MachineAgentTarget 是从 Catalog 解析出的可信执行目标；机器调用方不得提交 Agent、版本或 Endpoint。
type MachineAgentTarget struct {
	AgentID        string
	InstallationID string
	VersionID      string
	InputSchemaURI string
	Endpoint       string
	Transport      string
	Revision       uint64
}

// ResolveMachineAgentTarget resolves only the installation bound into the
// authenticated machine grant. It fails closed unless the installation and
// definition/version are active/published and the latest desired deployment
// is observed ready. A pending/failed rollout never falls back to an older
// endpoint.
// ResolveMachineAgentTarget 只解析机器授权绑定的安装实例；安装、Definition、Version 或最新部署未就绪时拒绝，
// 不回退到旧 Endpoint。
func (m *Module) ResolveMachineAgentTarget(ctx context.Context, scope sharedkernel.Scope) (MachineAgentTarget, error) {
	if m == nil || m.store == nil || scope.Validate() != nil || strings.TrimSpace(scope.AgentInstanceID) == "" {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	installation, err := m.store.GetInstallation(ctx, scope.AgentInstanceID)
	if err != nil || installation.ID != scope.AgentInstanceID || installation.TenantID != scope.TenantID ||
		installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID || installation.Status != InstallationActive {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	version, err := m.store.GetVersion(ctx, installation.VersionID)
	if err != nil || version.ID != installation.VersionID || version.Status != DefinitionPublished {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	var manifest agentManifest
	if json.Unmarshal(version.Manifest, &manifest) != nil || !schemaRef(manifest.Schemas.Input) {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	definition, err := m.store.GetDefinition(ctx, version.DefinitionID)
	if err != nil || definition.ID != version.DefinitionID || definition.Status != DefinitionPublished || definition.AgentKey != installation.AgentID {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	deployments, err := m.store.ListDeployments(ctx, installation.TenantID, installation.DepartmentID, installation.ApplicationID, installation.ID, 1)
	if err != nil || len(deployments) != 1 {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	deployment := deployments[0]
	if deployment.TenantID != installation.TenantID || deployment.DepartmentID != installation.DepartmentID || deployment.ApplicationID != installation.ApplicationID ||
		deployment.AgentInstallationID != installation.ID || deployment.AgentVersionID != version.ID || deployment.Status != DeploymentReady ||
		deployment.DesiredRevision == 0 || deployment.ObservedRevision != deployment.DesiredRevision || !validDeploymentEndpoint(deployment.EndpointRef, deployment.Transport) {
		return MachineAgentTarget{}, ErrMachineTargetUnavailable
	}
	return MachineAgentTarget{AgentID: definition.AgentKey, InstallationID: installation.ID, VersionID: version.ID,
		InputSchemaURI: manifest.Schemas.Input, Endpoint: deployment.EndpointRef, Transport: deployment.Transport, Revision: installation.Revision}, nil
}
