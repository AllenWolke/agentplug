package main

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
)

// identityPolicyAssetControl keeps policy management behind current Identity
// roles. The runtime resolver remains a separate read-only execution port.
// identityPolicyAssetControl 使用 Identity 当前角色判权；运行时 Resolver 仍是独立读取端口。
type identityPolicyAssetControl struct{ store identity.Store }

func (a identityPolicyAssetControl) AuthorizePolicyAsset(ctx context.Context, actor policyasset.Actor, action policyasset.Action, target policyasset.Scope) error {
	return a.authorizePolicyAction(ctx, actor, action, target, "policy.manage")
}

func (a identityPolicyAssetControl) AuthorizeTypedPolicyAsset(ctx context.Context, actor policyasset.Actor, action policyasset.Action, target policyasset.Scope, typ policyasset.AssetType) error {
	permissionAction := "policy.manage"
	switch typ {
	case policyasset.AssetPrompt:
		permissionAction = "prompt.manage"
	case policyasset.AssetTool:
		permissionAction = "tool.manage"
	case "", policyasset.AssetModel, policyasset.AssetMemory, policyasset.AssetKnowledge, policyasset.AssetRuntime:
	default:
		return policyasset.ErrForbidden
	}
	return a.authorizePolicyAction(ctx, actor, action, target, permissionAction)
}

func (a identityPolicyAssetControl) authorizePolicyAction(ctx context.Context, actor policyasset.Actor, action policyasset.Action, target policyasset.Scope, permissionAction string) error {
	if action != policyasset.ActionRead && action != policyasset.ActionCreate && action != policyasset.ActionUpdate && action != policyasset.ActionPublish {
		return policyasset.ErrForbidden
	}
	if a.store == nil || actor.PrincipalType != string(identity.PrincipalUser) || strings.TrimSpace(actor.PrincipalID) == "" ||
		actor.TenantID == "" || actor.DepartmentID == "" || actor.ApplicationID == "" {
		return policyasset.ErrForbidden
	}
	principal, err := a.store.GetPrincipal(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		if errors.Is(err, identity.ErrPrincipalNotFound) {
			return policyasset.ErrForbidden
		}
		return err
	}
	if !principal.IsActive || principal.TenantID != actor.TenantID || target.TenantID != actor.TenantID {
		return policyasset.ErrForbidden
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, permissionAction, target.TenantID, target.DepartmentID, target.ApplicationID); handled {
		return controlPermissionError(err, policyasset.ErrForbidden)
	}
	if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin") {
		return nil
	}
	if target.DepartmentID != actor.DepartmentID {
		return policyasset.ErrForbidden
	}
	if hasCatalogRole(principal.Roles, "department_admin") {
		return nil
	}
	if target.ApplicationID == actor.ApplicationID && hasCatalogRole(principal.Roles, "application_admin") {
		return nil
	}
	return policyasset.ErrForbidden
}
