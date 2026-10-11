package main

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/usagecost"
)

// identityUsageControl is the local policy adapter for usage reads and budgets.
// Role and account state are reloaded for every request from Identity.
// identityUsageControl 是浏览器用量查询的本地授权适配器，每次均重读 Identity 状态。
type identityUsageControl struct{ store identity.Store }

func (a identityUsageControl) AuthorizeUsageCost(ctx context.Context, actor usagecost.Actor, action usagecost.UsageAction, scope usagecost.Scope) error {
	if a.store == nil || action != usagecost.ActionReadUsage && action != usagecost.ActionManageLedgerBudget || actor.PrincipalType != string(identity.PrincipalUser) ||
		strings.TrimSpace(actor.PrincipalID) == "" || actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" ||
		scope.TenantID != actor.TenantID || scope.DepartmentID != actor.DepartmentID || scope.ApplicationID != actor.ApplicationID {
		return usagecost.ErrUsageForbidden
	}
	principal, err := a.store.GetPrincipal(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		if errors.Is(err, identity.ErrPrincipalNotFound) {
			return usagecost.ErrUsageForbidden
		}
		return err
	}
	if !principal.IsActive || principal.TenantID != actor.TenantID {
		return usagecost.ErrUsageForbidden
	}
	permissionAction := "platform.monitor"
	if action == usagecost.ActionManageLedgerBudget {
		permissionAction = "model.configure"
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, permissionAction, scope.TenantID, scope.DepartmentID, scope.ApplicationID); handled {
		return controlPermissionError(err, usagecost.ErrUsageForbidden)
	}
	if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin") {
		return nil
	}
	return usagecost.ErrUsageForbidden
}
