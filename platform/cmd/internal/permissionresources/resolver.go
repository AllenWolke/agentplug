package permissionresources

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Catalog interface {
	GetInstallation(context.Context, string) (catalog.Installation, error)
	GetVersion(context.Context, string) (catalog.Version, error)
	GetDefinition(context.Context, string) (catalog.Definition, error)
}

// The published policy bounds which capability resources an installation can
// use; it does not give the caller or executor any resource Grant.
type PublishedResolver struct {
	catalog  Catalog
	policies policyasset.Resolver
}

func (r PublishedResolver) ResolvePermissionResource(ctx context.Context, scope sharedkernel.Scope, typ, id string) (identity.PermissionResource, error) {
	if r.catalog == nil || r.policies == nil || scope.Validate() != nil || scope.InstallationID == "" || scope.AgentInstanceID != scope.InstallationID || id == "" {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	resource, err := resolvePublishedInstallation(ctx, r.catalog, scope, scope.InstallationID)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	scope.AgentID, scope.AgentVersionID = resource.AgentID, resource.AgentVersionID
	policy, err := r.policies.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	if policy.Validate() != nil {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	matched := false
	switch typ {
	case "agent_installation":
		matched = id == scope.InstallationID
	case "model":
		matched = policy.ModelProfileID == id
	case "tool":
		matched = slices.Contains(policy.Tool.AllowedTools, id)
	case "knowledge":
		matched = slices.Contains(policy.Knowledge.AllowedScopes, id)
	case "memory":
		matched = policy.MemoryPolicyID == id
	case "skill":
		matched = slices.Contains(policy.Runtime.AllowedSkills, id)
	}
	if !matched {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	return identity.PermissionResource{Type: typ, ID: id, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID}, nil
}

func NewPublishedResolver(catalog Catalog, policies policyasset.Resolver) PublishedResolver {
	return PublishedResolver{catalog: catalog, policies: policies}
}

func (r PublishedResolver) ResolvePermissionRunAvailability(ctx context.Context, scope sharedkernel.Scope) (string, error) {
	if r.catalog == nil || scope.Validate() != nil || scope.InstallationID == "" || scope.AgentInstanceID != scope.InstallationID {
		return "", identity.ErrInvalidResource
	}
	installation, err := r.catalog.GetInstallation(ctx, scope.InstallationID)
	if err != nil {
		return "", err
	}
	if installation.ID != scope.InstallationID || installation.TenantID != scope.TenantID || installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID {
		return "", identity.ErrInvalidResource
	}
	if installation.Status != catalog.InstallationActive {
		return "RESOURCE_UNAVAILABLE", nil
	}
	version, err := r.catalog.GetVersion(ctx, installation.VersionID)
	if err != nil {
		return "", err
	}
	if version.ID != installation.VersionID || version.DefinitionID == "" {
		return "", identity.ErrInvalidResource
	}
	definition, err := r.catalog.GetDefinition(ctx, version.DefinitionID)
	if err != nil {
		return "", err
	}
	if definition.ID != version.DefinitionID || definition.AgentKey != installation.AgentID {
		return "", identity.ErrInvalidResource
	}
	if version.Status == catalog.DefinitionDraft || definition.Status == catalog.DefinitionDraft {
		return "RESOURCE_NOT_PUBLISHED", nil
	}
	if version.Status != catalog.DefinitionPublished || definition.Status != catalog.DefinitionPublished {
		return "RESOURCE_UNAVAILABLE", nil
	}
	// Reuse the full published snapshot/hash/manifest checks, not status alone.
	_, err = resolvePublishedInstallation(ctx, r.catalog, scope, scope.InstallationID)
	return "", err
}

func resolvePublishedInstallation(ctx context.Context, reader Catalog, scope sharedkernel.Scope, installationID string) (identity.PermissionResource, error) {
	installation, err := reader.GetInstallation(ctx, installationID)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	if installation.ID != installationID || installation.Status != catalog.InstallationActive || installation.TenantID != scope.TenantID || installation.DepartmentID != scope.DepartmentID || installation.ApplicationID != scope.ApplicationID {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	version, err := reader.GetVersion(ctx, installation.VersionID)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	if version.ID != installation.VersionID || version.Status != catalog.DefinitionPublished || version.Validate() != nil {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	definition, err := reader.GetDefinition(ctx, version.DefinitionID)
	if err != nil {
		return identity.PermissionResource{}, err
	}
	if definition.ID != version.DefinitionID || definition.AgentKey != installation.AgentID || definition.Status != catalog.DefinitionPublished || definition.Validate() != nil {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	if _, err := version.Snapshot(definition); err != nil {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	var manifest struct {
		AgentID string `json:"agent_id"`
	}
	if json.Unmarshal(version.Manifest, &manifest) != nil || manifest.AgentID != installation.AgentID {
		return identity.PermissionResource{}, identity.ErrInvalidResource
	}
	displayName := installation.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = definition.DisplayName
	}
	return identity.PermissionResource{Type: "agent_installation", ID: installationID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, InstallationID: installationID, AgentID: installation.AgentID, AgentVersionID: installation.VersionID, DisplayName: displayName}, nil
}
