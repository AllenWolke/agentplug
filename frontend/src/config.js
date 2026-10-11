export const ROLE_LABELS = Object.freeze({
  admin: "系统管理员",
  platform_admin: "平台管理员",
  department_admin: "部门管理员",
  application_admin: "应用管理员",
  release_admin: "发布管理员",
  prompt_admin: "Prompt 管理员",
  tool_admin: "Tool 管理员",
  operator: "业务操作员",
  reviewer: "审核员",
  auditor: "审计员"
});

export function rolesOf(user) {
  if (!user) return [];
  if (user.policy_mode === "v2") return [];
  return Array.isArray(user.roles) ? user.roles : String(user.roles || "").split(",").map((item) => item.trim()).filter(Boolean);
}

export function hasAnyRole(user, ...roles) {
  const owned = new Set(rolesOf(user));
  return roles.some((role) => owned.has(role));
}

function versionedUser(user) { return user?.policy_mode !== undefined && user.policy_mode !== "legacy" && user.policy_mode !== "shadow"; }
export function hasManagementAction(user, action) { return user?.policy_mode === "v2" && user.capabilities?.includes(action) === true; }
export function canManageUsers(user) { return versionedUser(user) ? hasManagementAction(user, "principal.read") : isPlatformAdmin(user); }
export function canManageAccessRequests(user) { return versionedUser(user) ? hasManagementAction(user, "access_request.decide") : isAppAdmin(user) || isPlatformAdmin(user); }
export function isSystemAdmin(user) { return versionedUser(user) ? hasManagementAction(user, "platform.monitor") : hasAnyRole(user, "system_admin", "admin"); }
export function isPlatformAdmin(user) { return versionedUser(user) ? hasManagementAction(user, "platform.monitor") : hasAnyRole(user, "platform_admin", "system_admin", "admin"); }
export function isAppAdmin(user) { return versionedUser(user) ? ["organization.manage", "authorization.change", "catalog.manage", "policy.manage"].some(action => hasManagementAction(user, action)) : hasAnyRole(user, "department_admin", "application_admin", "release_admin", "prompt_admin", "tool_admin"); }
export function canManagePolicyAssets(user) { return versionedUser(user) ? ["policy.manage", "prompt.manage", "tool.manage"].some(action => hasManagementAction(user, action)) : isAppAdmin(user); }
// This page reads global definitions. Scoped installation management stays
// available in ApplicationAgentInstallations through the current capabilities.
export function canManageCatalog(user) { return versionedUser(user) ? user?.policy_mode === "v2" && user.global_capabilities?.includes("catalog.manage") === true : isPlatformAdmin(user) || isAppAdmin(user); }
export function canConfigureModels(user) { return versionedUser(user) ? hasManagementAction(user, "model.configure") : isPlatformAdmin(user); }
export function canDevelopAgents(user) { return versionedUser(user) ? hasManagementAction(user, "agent.develop") : isPlatformAdmin(user) || isAppAdmin(user); }
// Application/department administrators manage only their authenticated
// department + application; platform/system roles retain tenant-wide access.
// 应用/部门管理员仅管理当前部门 + 应用；平台/系统角色仍有租户级权限。
export function isIntegrationAdmin(user) { return versionedUser(user) ? hasManagementAction(user, "machine.manage") : hasAnyRole(user, "application_admin", "department_admin", "platform_admin", "system_admin", "admin"); }
export function canAudit(user) { return versionedUser(user) ? hasManagementAction(user, "audit.metadata.read") : hasAnyRole(user, "auditor", "platform_admin", "department_admin", "application_admin", "admin"); }
export function canReview(user) { return hasAnyRole(user, "reviewer", "admin"); }
export function canReviewConversationDeletion(user) { return versionedUser(user) ? user?.policy_mode === "v2" && user.data_capabilities?.includes("business.review") === true : isAppAdmin(user); }

// The evaluation workspace is a per-scope control plane. Its handlers accept
// platform admins plus the scope's evaluation/application admins (mirror of
// platformauth.RequireAnyRole in evaluation/handler.go), so the route guard must
// grant the same roles instead of hiding the page from the administrator who
// owns the scope's data.
// 评测工作台是按作用域的控制面。其处理器接受平台管理员以及该作用域的
// evaluation/application 管理员（与 evaluation/handler.go 的 RequireAnyRole 对应），
// 因此路由守卫必须授予同样的角色，而不是把页面只留给平台管理员、对数据所属
// 作用域的管理员隐藏。
export function canUseEvaluationWorkspace(user) { return versionedUser(user) ? hasManagementAction(user, "evaluation.run") : hasAnyRole(user, "platform_admin", "system_admin", "admin", "evaluation_admin", "application_admin"); }

export function visibleApplications(user) {
  if (!user) return [];
  if (!user.application_id || !user.department_id || isPlatformAdmin(user)) return [];
  return [{ id: user.application_id, code: user.application_id, departmentId: user.department_id,
    departmentName: user.department_name || user.department_id, name: user.application_name || user.application_id,
    description: "查看当前应用的 Agent 与使用权限", accent: "violet", agents: [], path: "/workspace/application" }];
}

export function defaultLanding(user) {
  if (isSystemAdmin(user)) return "/system/operations";
  if (isPlatformAdmin(user)) return "/platform/overview";
  return "/workspace";
}
