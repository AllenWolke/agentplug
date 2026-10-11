package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrBusinessRouteUnavailable = errors.New("business route catalog binding unavailable")

// Catalog-owned fact Port, not an authorization decision. Endpoints remain
// internal to the execution composition and are never supplied by a model.
type BusinessRouteTarget struct {
	AgentID              string
	InstallationID       string
	InstallationRevision uint64
	VersionID            string
	DeploymentID         string
	DeploymentRevision   uint64
	ManifestHash         string
	ArtifactDigest       string
	InputSchemaURI       string
	OutputSchemaURI      string
	Endpoint             string
	Transport            string
	TaskTypes            []string
}
type BusinessRouteInstallationReader interface {
	ListRouteInstallations(context.Context, sharedkernel.Scope, []string) ([]Installation, error)
}

func routeIdentifier(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "*\x00\r\n")
}

func (m *Module) ResolveBusinessRouteTarget(ctx context.Context, scope sharedkernel.Scope, installationID string) (BusinessRouteTarget, error) {
	if m == nil || m.store == nil || scope.ValidateTrusted() != nil || !routeIdentifier(installationID) {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	installation, err := m.store.GetInstallation(ctx, installationID)
	if err != nil || installation.ID != installationID || installation.TenantID != scope.TenantID || installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID || installation.Status != InstallationActive || installation.Revision == 0 {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	version, err := m.store.GetVersion(ctx, installation.VersionID)
	if err != nil || version.ID != installation.VersionID || version.Status != DefinitionPublished || version.Validate() != nil {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	definition, err := m.store.GetDefinition(ctx, version.DefinitionID)
	if err != nil || definition.ID != version.DefinitionID || definition.AgentKey != installation.AgentID || definition.Status != DefinitionPublished || definition.Validate() != nil {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	var manifest struct {
		agentManifest
		Metadata struct {
			RouteTaskTypes []string `json:"route_task_types"`
		} `json:"metadata"`
	}
	if json.Unmarshal(version.Manifest, &manifest) != nil || manifest.AgentID != installation.AgentID || manifest.Version != version.SemanticVersion || len(manifest.Metadata.RouteTaskTypes) < 1 || len(manifest.Metadata.RouteTaskTypes) > 16 || !schemaRef(manifest.Schemas.Input) {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	seen := map[string]bool{}
	for _, task := range manifest.Metadata.RouteTaskTypes {
		if !routeIdentifier(task) || seen[task] {
			return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
		}
		seen[task] = true
	}
	deployments, err := m.store.ListDeployments(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID, installation.ID, 1)
	if err != nil || len(deployments) != 1 {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	deployment := deployments[0]
	if deployment.ID == "" || deployment.TenantID != scope.TenantID || deployment.DepartmentID != scope.DepartmentID || deployment.ApplicationID != scope.ApplicationID || deployment.AgentInstallationID != installation.ID || deployment.AgentVersionID != version.ID || deployment.Status != DeploymentReady || deployment.DesiredRevision == 0 || deployment.DesiredRevision != deployment.ObservedRevision || deployment.ManifestHash != version.ManifestHash || deployment.ArtifactDigest != version.ArtifactDigest || !validDeploymentEndpoint(deployment.EndpointRef, deployment.Transport) || deployment.Transport != manifest.Runtime.Transport {
		return BusinessRouteTarget{}, ErrBusinessRouteUnavailable
	}
	return BusinessRouteTarget{AgentID: installation.AgentID, InstallationID: installation.ID, InstallationRevision: installation.Revision, VersionID: version.ID, DeploymentID: deployment.ID, DeploymentRevision: deployment.DesiredRevision, ManifestHash: version.ManifestHash, ArtifactDigest: version.ArtifactDigest, InputSchemaURI: manifest.Schemas.Input, OutputSchemaURI: manifest.Schemas.Output, Endpoint: deployment.EndpointRef, Transport: deployment.Transport, TaskTypes: append([]string(nil), manifest.Metadata.RouteTaskTypes...)}, nil
}

func (m *Module) BusinessRouteCandidates(ctx context.Context, scope sharedkernel.Scope, allowedAgents []string, taskType string) ([]BusinessRouteTarget, error) {
	if m == nil || m.store == nil || scope.ValidateTrusted() != nil || !routeIdentifier(taskType) || len(allowedAgents) < 1 || len(allowedAgents) > 32 {
		return nil, ErrBusinessRouteUnavailable
	}
	allowed := map[string]bool{}
	for _, id := range allowedAgents {
		if !routeIdentifier(id) || allowed[id] {
			return nil, ErrBusinessRouteUnavailable
		}
		allowed[id] = true
	}
	reader, ok := m.store.(BusinessRouteInstallationReader)
	if !ok {
		return nil, ErrBusinessRouteUnavailable
	}
	installations, err := reader.ListRouteInstallations(ctx, scope, append([]string(nil), allowedAgents...))
	if err != nil || len(installations) > 128 {
		return nil, ErrBusinessRouteUnavailable
	}
	result := []BusinessRouteTarget{}
	seen := map[string]bool{}
	for _, installation := range installations {
		if installation.TenantID != scope.TenantID || installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID || !allowed[installation.AgentID] || seen[installation.ID] {
			return nil, ErrBusinessRouteUnavailable
		}
		seen[installation.ID] = true
		target, err := m.ResolveBusinessRouteTarget(ctx, scope, installation.ID)
		if err != nil {
			continue
		}
		if target.AgentID != installation.AgentID || target.VersionID != installation.VersionID || target.InstallationRevision != installation.Revision {
			return nil, ErrBusinessRouteUnavailable
		}
		for _, task := range target.TaskTypes {
			if task == taskType {
				result = append(result, target)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].InstallationID < result[j].InstallationID })
	return result, nil
}
