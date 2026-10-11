// Account purpose is derived from the server projection, never the username.
export function administrationKind(user, now = Date.now()) {
  if (user?.policy_mode !== "v2") return "";
  if (["platform", "company", "permission", "department"].includes(user.administration_kind)) return user.administration_kind;
  const bindings = (user.role_bindings || []).filter(binding => binding.subject_id === user.username && binding.status === "active" &&
    (!binding.starts_at || Date.parse(binding.starts_at) <= now) && (!binding.expires_at || Date.parse(binding.expires_at) > now));
  if (bindings.some(binding => binding.role_code === "super_admin")) return "platform";
  if (bindings.some(binding => binding.role_code === "tenant_admin" && Number(binding.role_version) === 2 && binding.scope?.scope_type === "tenant" && binding.scope.tenant_id === user.tenant_id)) return "company";
  if (bindings.some(binding => binding.role_code === "permission_admin")) return "permission";
  return bindings.some(binding => binding.role_code === "department_admin") ? "department" : "";
}

export function workspaceChoices(user, response) {
  const kind = administrationKind(user);
  const values = kind === "department" ? [...(response?.administration_workspaces || []), ...(response?.application_workspaces || [])]
    : kind ? response?.administration_workspaces : response?.application_workspaces;
  const allowed = Array.isArray(values) ? values.filter(value => value.scope_type === "application" && value.tenant_id === user.tenant_id && value.department_id && value.application_id) : [];
  return [...new Map(allowed.map(value => [JSON.stringify([value.tenant_id, value.department_id, value.application_id]), value])).values()];
}

export function businessAgentChoices(user, agents = []) {
  return administrationKind(user) ? agents.filter(agent => agent.access_status === "granted") : agents;
}

// Selection hints never confer access. Each switch and Agent operation is
// still checked by the server. Prefer exact, effective role/member contexts
// before broad department memberships that may include empty applications.
export function preferredWorkspaceIDs(user, response, now = Date.now()) {
  const roles = (user.role_bindings || []).filter(binding => binding.subject_id === user.username && binding.status === "active" && binding.scope?.tenant_id === user.tenant_id &&
    (!binding.starts_at || Date.parse(binding.starts_at) <= now) && (!binding.expires_at || Date.parse(binding.expires_at) > now));
  const members = (response?.items || []).filter(scope => scope.scope_type === "application" && scope.tenant_id === user.tenant_id);
  return [...new Set([...roles.map(binding => binding.scope.application_id), ...members.map(scope => scope.application_id), ...(response?.application_workspaces || []).filter(scope => scope.tenant_id === user.tenant_id).map(scope => scope.application_id)].filter(Boolean))];
}

export function departmentWorkspace(items, departmentID, currentApplication, preferredIDs = []) {
  const candidates = items.filter(item => item.department_id === departmentID);
  return candidates.find(item => item.application_id === currentApplication) || preferredIDs.map(id => candidates.find(item => item.application_id === id)).find(Boolean) || candidates[0];
}

export function canRequestOwnPermissions(user) {
  return user?.policy_mode === "v2" && !administrationKind(user) && user.self_service_permissions !== false;
}

export function canAssignDepartmentRoles(user, principal) {
  return principal?.id !== user?.username && principal?.tenant_id === user?.tenant_id &&
    ["platform", "company"].includes(administrationKind(user)) && user.capabilities?.includes("authorization.change") && user.capabilities?.includes("membership.manage");
}

export function isProtectedAdministratorBinding(binding) {
  return ["super_admin", "permission_admin"].includes(binding?.role_code) || binding?.role_code === "tenant_admin" && Number(binding.role_version) === 2;
}
