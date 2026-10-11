export const DAILY_AGENT_ACTIONS = Object.freeze([
  "discover", "run", "cancel", "history.read", "history.continue", "knowledge.search",
  "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write", "skill.load", "agent.delegate"
]);

const copyEntry = entry => ({ application_id: entry.application_id, installation_id: entry.installation_id,
  actions: [...new Set(entry.actions || [])].sort(), ...(entry.starts_at ? { starts_at: entry.starts_at } : {}), ...(entry.expires_at ? { expires_at: entry.expires_at } : {}) });

// Updating one visible Agent must preserve other application entries and
// advanced actions, including entries not present in the current Catalog page.
export function replaceDepartmentAgentEntry(entries, app, installation, update) {
  const existing = entries.find(entry => entry.application_id === app && entry.installation_id === installation);
  const others = entries.filter(entry => entry.application_id !== app || entry.installation_id !== installation).map(copyEntry);
  const value = update(existing ? copyEntry(existing) : null);
  if (value) others.push(copyEntry({ ...value, application_id: app, installation_id: installation }));
  return others.sort((a, b) => a.application_id.localeCompare(b.application_id) || a.installation_id.localeCompare(b.installation_id));
}

export function departmentAgentCommand({ state, tenant, department, entries, reason, key }) {
  if (!state || state.policy?.tenant_id !== tenant || state.policy?.department_id !== department || !state.can_manage || !Number.isSafeInteger(state.policy.revision) || state.policy.revision < 0) throw new Error("请重新读取部门授权配置");
  if (!reason.trim()) throw new Error("请填写本次调整原因");
  if (entries.length > 256) throw new Error("每个部门最多开通 256 个 Agent");
  if (entries.some(entry => !entry.actions?.length)) throw new Error("每个已开通 Agent 至少需要一个操作");
  return { tenant_id: tenant, department_id: department, expected_revision: state.policy.revision,
    migrate_existing: !state.managed, entries: entries.map(copyEntry), reason: reason.trim(), idempotency_key: key };
}

export const departmentAgentPendingStorageKey = (user, department) => `agentplug.pending-department-agent:${JSON.stringify([user.username, user.tenant_id, department])}`;

export function departmentAgentPolicyDifferences(before, after) {
  const key = entry => JSON.stringify([entry.application_id, entry.installation_id]);
  const old = new Map((before.entries || []).map(entry => [key(entry), copyEntry(entry)]));
  const next = new Map((after.entries || []).map(entry => [key(entry), copyEntry(entry)]));
  return [...new Set([...old.keys(), ...next.keys()])].flatMap(id => {
    const a = old.get(id), b = next.get(id);
    return JSON.stringify(a) === JSON.stringify(b) ? [] : [{ kind: !a ? "added" : !b ? "removed" : "changed", before: a, after: b }];
  });
}
