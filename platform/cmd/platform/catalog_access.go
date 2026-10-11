package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// identityCatalogAccess is the local adapter from Catalog's access port to
// Identity's authoritative SQL-backed grant evaluator. A service split can
// replace this adapter without changing Catalog's HTTP contract.
// identityCatalogAccess 是 Catalog 到 Identity 权威授权判断的本地 Adapter；拆分服务时可替换为远程实现。
type identityCatalogAccess struct {
	store identity.Store
}

func (a identityCatalogAccess) ProjectAgentActions(ctx context.Context, actor catalog.ControlActor, installations []string) (map[string]map[string]bool, error) {
	if a.store == nil || actor.PrincipalType != "user" || actor.PrincipalID == "" || actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" {
		return nil, catalog.ErrCatalogForbidden
	}
	repository, ok := a.store.(identity.PermissionRepository)
	if !ok {
		return nil, errors.New("permission repository unavailable")
	}
	snapshot, err := repository.PermissionSnapshot(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		return nil, err
	}
	if snapshot.Principal.Validate() != nil || !snapshot.Principal.IsActive || snapshot.Principal.ID != actor.PrincipalID || snapshot.Principal.Type != identity.PrincipalUser || snapshot.Principal.TenantID != actor.TenantID {
		return nil, catalog.ErrCatalogForbidden
	}
	if snapshot.Mode != "v2" && snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
		return nil, identity.ErrInvalidResource
	}
	result := make(map[string]map[string]bool, len(installations))
	now := time.Now().UTC()
	actions := []string{}
	for _, action := range identity.BuiltinPermissionActions() {
		if !action.Management && action.ResourceType == "agent_installation" {
			actions = append(actions, action.Code)
		}
	}
	for _, installation := range installations {
		if installation == "" || strings.ContainsAny(installation, "*\x00") {
			return nil, identity.ErrInvalidResource
		}
		if _, exists := result[installation]; exists {
			continue
		}
		projection := map[string]bool{}
		for _, action := range actions {
			if snapshot.Mode == "v2" {
				decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{Action: action, Scope: identity.ManagementScope{Type: "agent_installation", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, ResourceID: installation}, ResourceType: "agent_installation", ResourceID: installation, Now: now})
				if err != nil {
					return nil, err
				}
				projection[action] = decision.Allowed
			} else {
				decision, err := identity.CheckPrincipalAccess(ctx, a.store, sharedkernel.Scope{TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: installation}, identity.PrincipalUser, actor.PrincipalID, action)
				if err != nil {
					return nil, err
				}
				projection[action] = decision.Allowed
			}
		}
		result[installation] = projection
	}
	return result, nil
}

func (a identityCatalogAccess) CanDiscoverAgent(ctx context.Context, tenantID, departmentID, applicationID, installationID, principalType, principalID string) (bool, error) {
	decision, err := identity.CheckPrincipalAccess(ctx, a.store, sharedkernel.Scope{
		TenantID: tenantID, DepartmentID: departmentID, ApplicationID: applicationID, AgentInstanceID: installationID,
	}, identity.PrincipalType(principalType), principalID, "discover")
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// identityCatalogControl is the Catalog control-plane adapter. Roles are
// loaded from the authoritative Identity store; no browser-supplied role or
// request-body identity is trusted.
// identityCatalogControl 是 Catalog 控制面的 Identity Adapter；角色从权威存储读取。
type identityCatalogControl struct{ store identity.Store }

func (a identityCatalogControl) AuthorizeCatalogControl(ctx context.Context, actor catalog.ControlActor, action catalog.ControlAction, target catalog.ControlScope) error {
	if a.store == nil || actor.PrincipalType != string(identity.PrincipalUser) || strings.TrimSpace(actor.PrincipalID) == "" || strings.TrimSpace(actor.TenantID) == "" {
		return catalog.ErrCatalogForbidden
	}
	principal, err := a.store.GetPrincipal(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		if errors.Is(err, identity.ErrPrincipalNotFound) {
			return catalog.ErrCatalogForbidden
		}
		return err
	}
	if !principal.IsActive || principal.TenantID != actor.TenantID {
		return catalog.ErrCatalogForbidden
	}
	tenantID := strings.TrimSpace(target.TenantID)
	departmentID := strings.TrimSpace(target.DepartmentID)
	applicationID := strings.TrimSpace(target.ApplicationID)
	permissionAction := "catalog.manage"
	if action == catalog.ControlDeploy {
		permissionAction = "release.approve"
	}
	if action == catalog.ControlSubmit {
		permissionAction = "release.submit"
	}
	if action == catalog.ControlApprove {
		permissionAction = "release.approve"
	}
	if action == catalog.ControlRequestable {
		permissionAction = "catalog.requestable.read"
	}
	switch action {
	case catalog.ControlPromptTargets:
		permissionAction = "prompt.manage"
	case catalog.ControlToolTargets:
		permissionAction = "tool.manage"
	case catalog.ControlPolicyTargets:
		permissionAction = "policy.manage"
	case catalog.ControlAuthorizationTargets:
		permissionAction = "authorization.change"
	case catalog.ControlWorkloadTargets:
		permissionAction = "machine.manage"
	case catalog.ControlDelegationTargets:
		permissionAction = "delegation.manage"
	}
	if (action == catalog.ControlAuthorizationTargets || action == catalog.ControlWorkloadTargets || action == catalog.ControlDelegationTargets) && (tenantID == "" || departmentID == "" || applicationID == "") {
		return catalog.ErrCatalogForbidden
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, permissionAction, tenantID, departmentID, applicationID); handled {
		return controlPermissionError(err, catalog.ErrCatalogForbidden)
	}
	if action == catalog.ControlAuthorizationTargets || action == catalog.ControlWorkloadTargets || action == catalog.ControlDelegationTargets {
		return catalog.ErrCatalogForbidden
	}
	if action == catalog.ControlRequestable {
		if tenantID == actor.TenantID && departmentID != "" && departmentID == actor.DepartmentID && applicationID != "" && applicationID == actor.ApplicationID {
			return nil
		}
		return catalog.ErrCatalogForbidden
	}
	if action == catalog.ControlDeploy {
		// Runtime endpoints and desired deployment configuration are platform
		// control-plane authority; app/department admins may install, but cannot
		// point the platform at an arbitrary endpoint.
		// Runtime Endpoint 与期望部署配置属于平台控制面权限；应用/部门管理员可安装，但不能指定任意运行地址。
		if hasCatalogRole(principal.Roles, "system_admin", "admin") {
			return nil
		}
		if tenantID != "" && tenantID == actor.TenantID && hasCatalogRole(principal.Roles, "platform_admin") {
			return nil
		}
		return catalog.ErrCatalogForbidden
	}
	if tenantID != "" && departmentID == "" && applicationID == "" {
		// Only platform-wide administrators may enumerate tenant installations;
		// app and department admins always need the full exact scope.
		// 只有平台级管理员可以枚举租户安装；部门/应用管理员必须指定完整作用域。
		if hasCatalogRole(principal.Roles, "system_admin", "admin") ||
			(tenantID == actor.TenantID && hasCatalogRole(principal.Roles, "platform_admin")) {
			return nil
		}
		return catalog.ErrCatalogForbidden
	}
	if tenantID == "" && departmentID == "" && applicationID == "" {
		// Definition/version administration is global, so only explicit platform
		// roles may access it; department/application roles cannot enumerate it.
		if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin") {
			return nil
		}
		return catalog.ErrCatalogForbidden
	}
	if tenantID == "" || departmentID == "" || applicationID == "" {
		return catalog.ErrCatalogForbidden
	}
	if hasCatalogRole(principal.Roles, "system_admin", "admin") {
		return nil
	}
	if tenantID != actor.TenantID || tenantID != principal.TenantID {
		return catalog.ErrCatalogForbidden
	}
	if hasCatalogRole(principal.Roles, "platform_admin") {
		return nil
	}
	if departmentID != actor.DepartmentID {
		return catalog.ErrCatalogForbidden
	}
	if hasCatalogRole(principal.Roles, "department_admin") {
		return nil
	}
	if applicationID == actor.ApplicationID && hasCatalogRole(principal.Roles, "application_admin") {
		return nil
	}
	return catalog.ErrCatalogForbidden
}

func hasCatalogRole(roles []string, accepted ...string) bool {
	set := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		set[strings.TrimSpace(role)] = struct{}{}
	}
	for _, role := range accepted {
		if _, ok := set[role]; ok {
			return true
		}
	}
	return false
}
