package main

import (
	"context"
	"strings"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type identityAuditMetadataControl struct{ store identity.Store }

func (a identityAuditMetadataControl) Authorize(ctx context.Context, actor sharedkernel.Scope, target audit.MetadataScope) error {
	if actor.Validate() != nil || actor.PrincipalType != "user" || target.Validate() != nil {
		return audit.ErrMetadataForbidden
	}
	principal, err := a.store.GetPrincipal(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		return controlPermissionError(err, audit.ErrMetadataForbidden)
	}
	if !principal.IsActive || principal.TenantID != actor.TenantID {
		return audit.ErrMetadataForbidden
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, "audit.metadata.read", target.TenantID, target.DepartmentID, target.ApplicationID); handled {
		return controlPermissionError(err, audit.ErrMetadataForbidden)
	}
	// Preserve the legacy current-workspace boundary. Broader audit scopes only
	// become available through explicit versioned bindings.
	if target.Type != "application" || target.TenantID != actor.TenantID || target.DepartmentID != actor.DepartmentID || target.ApplicationID != actor.ApplicationID {
		return audit.ErrMetadataForbidden
	}
	for _, role := range principal.Roles {
		switch strings.TrimSpace(role) {
		case "system_admin", "admin", "platform_admin", "auditor":
			return nil
		}
	}
	return audit.ErrMetadataForbidden
}
