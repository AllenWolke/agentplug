package permissionresources

import (
	"context"
	"strings"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type InstallationResolver struct {
	reader    catalog.AvailableAgentReader
	published Catalog
}

func NewInstallationResolver(reader catalog.AvailableAgentReader) InstallationResolver {
	return InstallationResolver{reader: reader}
}

func NewVerifiedInstallationResolver(reader catalog.AvailableAgentReader, published Catalog) InstallationResolver {
	return InstallationResolver{reader: reader, published: published}
}

func (r InstallationResolver) ResolveAgentInstallation(ctx context.Context, scope sharedkernel.Scope, installationID string) (identity.AgentInstallation, error) {
	if r.reader == nil || strings.TrimSpace(installationID) == "" {
		return identity.AgentInstallation{}, identity.ErrAgentInstallationNotFound
	}
	items, err := r.reader.ListAvailableAgents(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return identity.AgentInstallation{}, err
	}
	for _, item := range items {
		if item.InstallationID == installationID {
			if r.published != nil {
				resource, err := resolvePublishedInstallation(ctx, r.published, scope, installationID)
				if err != nil {
					return identity.AgentInstallation{}, err
				}
				if resource.AgentID != item.AgentID || resource.AgentVersionID != item.VersionID {
					return identity.AgentInstallation{}, identity.ErrInvalidResource
				}
			}
			return identity.AgentInstallation{AgentID: item.AgentID}, nil
		}
	}
	return identity.AgentInstallation{}, identity.ErrAgentInstallationNotFound
}
