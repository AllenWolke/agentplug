package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/modelgovernance"
)

// identityModelGovernanceControl resolves roles from the authoritative Identity
// store. The browser's scope and role claims are never sufficient for control.
// identityModelGovernanceControl 从 Identity 权威存储读取角色，不信任浏览器角色声明。
type identityModelGovernanceControl struct{ store identity.Store }

func (a identityModelGovernanceControl) AuthorizeModelGovernance(ctx context.Context, actor modelgovernance.Actor, action modelgovernance.Action, target modelgovernance.Scope) error {
	principal, err := activeIdentityPrincipal(a.store, ctx, actor.PrincipalType, actor.PrincipalID, actor.TenantID)
	if err != nil {
		if errors.Is(err, errControlActorForbidden) {
			return modelgovernance.ErrForbidden
		}
		return err
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, "model.configure", target.TenantID, target.DepartmentID, target.ApplicationID); handled {
		return controlPermissionError(err, modelgovernance.ErrForbidden)
	}
	if target.IsGlobal() && action != modelgovernance.ActionManageDeployment && action != modelgovernance.ActionManagePolicy {
		if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin") {
			return nil
		}
		return modelgovernance.ErrForbidden
	}
	if actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" {
		return modelgovernance.ErrForbidden
	}
	if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin") {
		return nil
	}
	return modelgovernance.ErrForbidden
}
