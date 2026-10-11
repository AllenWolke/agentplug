export const PERMISSION_BATCH_LIMIT = 50;
export const BASIC_REQUEST_ACTIONS = ["discover", "run", "cancel", "history.read", "history.continue"];
const statuses = ["pending", "blocked", "succeeded", "failed", "cancelled"];
const validKey = value => typeof value === "string" && value.length > 0 && value.length <= 128 && value.trim() === value && !/[\0\r\n/\\:]/.test(value);

// Keep whole records across pages. A page-level checkbox must never discard
// people selected on another page or silently exceed the reviewed batch limit.
export function selectBatchRecords(current, records, checked) {
  const values = new Map(current.map(item => [item.id, item]));
  for (const item of records) checked ? values.set(item.id, item) : values.delete(item.id);
  if (values.size > PERMISSION_BATCH_LIMIT) throw new Error("一次最多选择 50 项，请分批办理。");
  return [...values.values()];
}

export function batchCounts(items = []) {
  return Object.fromEntries(statuses.map(status => [status, items.filter(item => item.status === status).length]));
}

export function batchStorageKey(user, kind) {
  if (!user?.username || !user?.tenant_id || !["authorization", "decision"].includes(kind)) throw new Error("无法确认当前办理账号。");
  return `agentplug.permission-batch.v1:${encodeURIComponent(user.tenant_id)}:${encodeURIComponent(user.username)}:${kind}`;
}

export function readBatchKey(storage, namespace) {
  try { const value = storage?.getItem(namespace); return validKey(value) ? value : ""; } catch { return ""; }
}

export function saveBatchKey(storage, namespace, key) {
  if (!validKey(key)) throw new Error("批次编号无效，请重新核对。");
  try {
    storage.setItem(namespace, key);
    if (storage.getItem(namespace) !== key) throw new Error("storage verification failed");
  } catch { throw new Error("浏览器无法保存批次编号。请允许本页使用会话存储后再办理。"); }
}

export function validateBatchResult(batch, key, user, kind) {
  if (!batch || batch.actor_id !== user.username || batch.actor_tenant_id !== user.tenant_id || batch.change?.idempotency_key !== key || batch.change.kind !== kind || !Array.isArray(batch.items) || !batch.items.length || batch.items.length > PERMISSION_BATCH_LIMIT || batch.items.some((item, index) => item.index !== index || !statuses.includes(item.status))) throw new Error("批次结果无法核对，请保留原编号并重新查询。");
  return batch;
}

// One explicit authorization permits a bounded run. A failed POST stops the
// loop immediately: neither network failure nor a later GET replays a write.
export async function continueBatchSteps(client, { key, batch, user, kind, onResult = () => {}, isActive = () => true }) {
  let result = validateBatchResult(batch, key, user, kind);
  for (let step = 0; step < PERMISSION_BATCH_LIMIT && isActive() && batchCounts(result.items).pending; step++) {
    result = validateBatchResult(await client.continuePermissionBatch(key), key, user, kind);
    onResult(result);
  }
  return result;
}

export function commonRequestScope(requests) {
  if (!requests.length) return null;
  const scopes = requests.map(item => item.scope);
  const first = scopes[0];
  if (!first?.tenant_id || scopes.some(scope => !scope || scope.tenant_id !== first.tenant_id || !["tenant", "department", "application"].includes(scope.scope_type) || scope.scope_type !== "tenant" && !scope.department_id || scope.scope_type === "application" && !scope.application_id)) return null;
  const scope = { scope_type: "tenant", tenant_id: first.tenant_id };
  if (first.department_id && scopes.every(item => item.department_id === first.department_id)) Object.assign(scope, { scope_type: "department", department_id: first.department_id });
  if (scope.department_id && first.application_id && scopes.every(item => item.application_id === first.application_id)) Object.assign(scope, { scope_type: "application", application_id: first.application_id });
  return scope;
}

export function duplicateRequestSubjects(requests) {
  const counts = new Map();
  for (const item of requests) counts.set(item.subject_id, (counts.get(item.subject_id) || 0) + 1);
  return [...counts].filter(([, count]) => count > 1).map(([id]) => id);
}

export function basicRequestedItems(request) {
  return request.items.filter(item => item.kind === "role" ? item.role_code === "operator" : item.kind === "resource" && (!item.resource_type || item.resource_type === "agent_installation") && BASIC_REQUEST_ACTIONS.includes(item.action)).map(item => item.id);
}

export function decisionBatchCommand({ user, requests, profiles, approved, mode, reason, key }) {
  const scope = commonRequestScope(requests);
  if (!scope || !["approve", "reject"].includes(mode) || !reason.trim() || requests.length > PERMISSION_BATCH_LIMIT || duplicateRequestSubjects(requests).length || requests.some(item => item.status !== "pending" || item.subject_id === user.username)) throw new Error("请核对申请范围、申请人及办理事项。");
  return { kind: "decision", scope, idempotency_key: key, reason: reason.trim(), items: requests.map(request => {
    const profile = profiles[request.subject_id];
    const ids = mode === "reject" ? [] : (approved[request.id] || []);
    if (profile?.principal?.id !== request.subject_id || !profile.principal.revision || profile.policy_mode !== "v2" || !profile.principal.is_active || mode === "approve" && !ids.length || ids.some(id => !request.items.some(item => item.id === id))) throw new Error("每份批准申请都需选择至少一项，且申请人必须有效。");
    return { decision: { request_id: request.id, expected_revision: request.revision, expected_subject_revision: profile.principal.revision, decision: mode === "reject" ? "rejected" : "approved", approved_item_ids: [...ids] } };
  }) };
}

export function departmentBatchCommand({ user, principals, profiles, department, role, expiresAt, reason, key, newID }) {
  if (!department?.tenant_id || department.tenant_id !== user.tenant_id || !department.department_id || !principals.length || principals.length > PERMISSION_BATCH_LIMIT || !["keep", "member", "administrator"].includes(role) || !reason.trim()) throw new Error("请选择本公司部门、用户和办理原因。");
  const scope = { scope_type: "department", tenant_id: department.tenant_id, department_id: department.department_id };
  return { kind: "authorization", scope, idempotency_key: key, reason: reason.trim(), items: principals.map(principal => {
    const profile = profiles[principal.id];
    if (principal.id === user.username || profile?.principal?.id !== principal.id || !profile.principal.revision || !profile.principal.is_active || profile.principal.tenant_id !== scope.tenant_id || profile.policy_mode !== "v2") throw new Error("只能为本公司的其他有效用户办理，请刷新后核对。");
    const member = (profile.memberships || []).find(item => item.scope?.scope_type === "department" && item.scope.tenant_id === scope.tenant_id && item.scope.department_id === scope.department_id);
    const validity = { ...(member?.starts_at ? { starts_at: member.starts_at } : {}), ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : member?.expires_at ? { expires_at: member.expires_at } : {}) };
    const authorization = { subject_type: "user", subject_id: principal.id, expected_revision: profile.principal.revision,
      memberships: [{ id: member?.id || newID(), scope, expected_revision: member?.revision || 0, status: "active", ...validity }] };
    if (role !== "keep") authorization.revoke_binding_ids = (profile.role_bindings || []).filter(item => item.role_code === "department_admin" && item.status === "active" && item.scope?.scope_type === "department" && item.scope.tenant_id === scope.tenant_id && item.scope.department_id === scope.department_id).map(item => item.id);
    if (role === "administrator") authorization.preset = { preset_code: "department_admin", preset_version: 2, scope, ...validity };
    return { authorization };
  }) };
}

export async function loadBatchProfiles(client, ids) {
  const profiles = {};
  const unique = [...new Set(ids)];
  for (let index = 0; index < unique.length; index += 5) {
    const group = unique.slice(index, index + 5);
    const results = await Promise.all(group.map(id => client.identityAccessProfile(id)));
    group.forEach((id, offset) => { profiles[id] = results[offset]; });
  }
  return profiles;
}

export function agentUseBatchCommand({ user, principals, profiles, pack, joinDepartment, expiresAt, reason, key, newID }) {
  const scope = pack?.scope;
  if (scope?.scope_type !== "agent_installation" || scope.tenant_id !== user.tenant_id || !scope.department_id || !scope.application_id || !scope.resource_id || !pack.agent_version_id || !/^[a-f0-9]{64}$/.test(pack.package_digest || "") || !principals.length || principals.length > PERMISSION_BATCH_LIMIT || !reason.trim()) throw new Error("请核对本公司部门、Agent 配置、用户和办理原因。");
  const department = { scope_type: "department", tenant_id: scope.tenant_id, department_id: scope.department_id };
  const command = { kind: "authorization", scope: { scope_type: "application", tenant_id: scope.tenant_id, department_id: scope.department_id, application_id: scope.application_id }, idempotency_key: key, reason: reason.trim(), items: principals.map(principal => {
    const profile = profiles[principal.id];
    if (principal.id === user.username || profile?.principal?.id !== principal.id || !profile.principal.revision || !profile.principal.is_active || profile.principal.tenant_id !== scope.tenant_id || profile.policy_mode !== "v2") throw new Error("只能为本公司的其他有效用户办理，请刷新后核对。");
    const members = profile.memberships || [];
    const existing = members.find(item => item.scope?.scope_type === "department" && item.scope.tenant_id === scope.tenant_id && item.scope.department_id === scope.department_id);
    const now = Date.now();
    const admitted = members.some(item => item.status === "active" && (!item.starts_at || Date.parse(item.starts_at) <= now) && (!item.expires_at || Date.parse(item.expires_at) > now) && ["department", "application"].includes(item.scope?.scope_type) && item.scope.tenant_id === scope.tenant_id && item.scope.department_id === scope.department_id && (!item.scope.application_id || item.scope.application_id === scope.application_id));
    const validity = expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {};
    return { authorization: { subject_type: "user", subject_id: principal.id, expected_revision: profile.principal.revision,
      agent_use: { scope: { ...scope }, agent_version_id: pack.agent_version_id, package_digest: pack.package_digest, ...validity },
      ...(joinDepartment && !admitted && !existing ? { memberships: [{ id: newID(), scope: department, status: "active", ...validity }] } : {}) } };
  }) };
  if (command.items.some(item => item.authorization.memberships?.length)) command.scope = department;
  return command;
}
