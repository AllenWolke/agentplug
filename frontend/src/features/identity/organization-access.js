import { administrationKind } from "./administration-state.js";

export const effectiveAccess = (item, now = Date.now()) => item.status === "active" && (!item.starts_at || Date.parse(item.starts_at) <= now) && (!item.expires_at || Date.parse(item.expires_at) > now);
export const scopeContains = (outer, inner) => ["tenant_id", "department_id", "application_id", "resource_id"].every(key => !outer[key] || outer[key] === inner[key]);

export function latestPresets(values) {
  const latest = new Map();
  for (const item of values) if (!latest.has(item.preset_code) || Number(item.preset_version) > Number(latest.get(item.preset_code).preset_version)) latest.set(item.preset_code, item);
  return [...latest.values()];
}

export function membershipTargets(user, principal, workspaces) {
  const targets = new Map();
  const add = scope => targets.set(JSON.stringify(scope), scope);
  if (principal.tenant_id !== user.tenant_id) return [];
  for (const item of workspaces) {
    if (item.tenant_id !== principal.tenant_id || !item.management_actions?.includes("membership.manage")) continue;
    const department = { scope_type: "department", tenant_id: item.tenant_id, department_id: item.department_id };
    if (administrationKind(user) !== "permission" || (user.delegations || []).some(d => effectiveAccess(d) && d.management_actions?.includes("membership.manage") && scopeContains(d.scope, department))) add(department);
    if (item.application_id) add({ scope_type: "application", tenant_id: item.tenant_id, department_id: item.department_id, application_id: item.application_id });
  }
  return [...targets.values()];
}

export function grantScopes(profile, preset, workspaces) {
  const members = (profile?.memberships || []).filter(item => effectiveAccess(item));
  const scopes = new Map();
  const add = scope => { if (preset?.scope_types?.includes(scope.scope_type)) scopes.set(JSON.stringify(scope), { scope }); };
  for (const member of members) add(member.scope);
  for (const item of workspaces) {
    const scope = { scope_type: "application", tenant_id: item.tenant_id, department_id: item.department_id, application_id: item.application_id };
    if (item.management_actions?.includes("authorization.change") && members.some(member => scopeContains(member.scope, scope))) add(scope);
  }
  return [...scopes.values()];
}

export function delegatedAgentTargets(user, targets, scope, purpose = "authorization.change") {
  if (!["department", "permission"].includes(administrationKind(user))) return targets;
  const state = user.department_agent_policy;
  if (administrationKind(user) === "department" && state?.managed) {
    const policy = state.policy;
    if (policy?.tenant_id !== scope.tenant_id || policy?.department_id !== scope.department_id) return [];
    const now = Date.now();
    return targets.filter(item => (policy.entries || []).some(entry => entry.application_id === scope.application_id && entry.installation_id === item.id &&
      entry.actions?.length && (!entry.expires_at || Date.parse(entry.expires_at) > now)));
  }
  return targets.filter(item => (user.delegations || []).some(d => effectiveAccess(d) && d.management_actions?.includes(purpose) && scopeContains(d.scope, { ...scope, resource_id: item.id }) &&
    (d.resources?.includes(item.id) || d.resource_bindings?.some(r => r.installation_id === item.id))));
}
