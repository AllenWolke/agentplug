export function projectSessionIdentity(identity, projection) {
  if (projection.policy_mode !== "v2") return { ...identity, ...projection };
  const scope = projection.scope;
  if (scope?.scope_type !== "application" || !scope.tenant_id || !scope.department_id || !scope.application_id || scope.tenant_id !== identity.tenant_id) throw new Error("工作空间权限响应无效");
  return { ...identity, ...projection, tenant_id: scope.tenant_id, department_id: scope.department_id, application_id: scope.application_id,
    department_name: scope.department_id === identity.department_id ? identity.department_name : scope.department_id };
}

export function workspaceDisplayIdentity(identity, workspaces) {
  const current = workspaces.find(item => ["tenant_id", "department_id", "application_id"].every(key => item[key] === identity[key]));
  if (!current) return identity;
  return { ...identity, ...(current.workspace_name ? { workspace_name: current.workspace_name } : {}), department_name: current.department_name || identity.department_name,
    application_name: current.application_name || identity.application_name };
}

export function permissionRequestScopes(response, tenantID) {
  const values = [...(response?.items || []), ...(response?.application_workspaces || [])];
  const scopes = values.filter(value => value.tenant_id === tenantID && ["tenant", "department", "application"].includes(value.scope_type) &&
    (value.scope_type === "tenant" || value.department_id) && (value.scope_type !== "application" || value.application_id))
    .map(value => ({ scope_type: value.scope_type, tenant_id: value.tenant_id,
      ...(value.scope_type !== "tenant" ? { department_id: value.department_id } : {}),
      ...(value.scope_type === "application" ? { application_id: value.application_id } : {}) }));
  return [...new Map(scopes.map(scope => [JSON.stringify(scope), scope])).values()];
}
