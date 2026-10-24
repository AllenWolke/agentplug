package permissionresources

import (
	"context"
	"slices"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ValidateWorkloadBindingVersions permits explicitly retained, published
// releases of the installation's definition. Each release keeps its own policy.
func (r PublishedResolver) ValidateWorkloadBindingVersions(ctx context.Context, scope sharedkernel.Scope, versions []string) error {
	if r.catalog == nil || r.policies == nil || scope.Validate() != nil || scope.InstallationID == "" || scope.AgentInstanceID != scope.InstallationID || len(versions) == 0 || len(versions) > 32 || !slices.Contains(versions, scope.AgentVersionID) {
		return identity.ErrInvalidResource
	}
	current, err := resolvePublishedInstallation(ctx, r.catalog, scope, scope.InstallationID)
	if err != nil {
		return err
	}
	if current.AgentID != scope.AgentID || current.AgentVersionID != scope.AgentVersionID {
		return identity.ErrInvalidResource
	}
	primary, err := r.catalog.GetVersion(ctx, current.AgentVersionID)
	if err != nil {
		return err
	}
	definition, err := r.catalog.GetDefinition(ctx, primary.DefinitionID)
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(versions))
	for _, id := range versions {
		if id == "" || len(id) > 128 || seen[id] {
			return identity.ErrInvalidResource
		}
		seen[id] = true
		version, err := r.catalog.GetVersion(ctx, id)
		if err != nil {
			return err
		}
		if version.ID != id || version.DefinitionID != primary.DefinitionID || version.Status != catalog.DefinitionPublished || version.Validate() != nil {
			return identity.ErrInvalidResource
		}
		if _, err := version.Snapshot(definition); err != nil {
			return identity.ErrInvalidResource
		}
		pinned := scope
		pinned.AgentVersionID = id
		policy, err := r.policies.Resolve(ctx, pinned, id)
		if err != nil {
			return err
		}
		if policy.Validate() != nil {
			return identity.ErrInvalidResource
		}
	}
	return nil
}
