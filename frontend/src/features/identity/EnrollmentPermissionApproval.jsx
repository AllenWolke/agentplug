import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { actionName, installationName, resourceName, roleName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";

const actions = ["discover", "run", "history.read", "history.continue", "history.revise", "history.regenerate", "cancel", "history.share", "history.export", "history.delete.request"];

export function EnrollmentPermissionApproval({ item, catalog, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [operatorIdentity, setOperatorIdentity] = useState(false);
  const [selected, setSelected] = useState({});
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [command, setCommand] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const candidates = catalog.filter(agent => item.requested_agent_ids?.includes(agent.agent_id));
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      const next = { enrollment_id: item.id, expected_revision: item.revision, operator_identity: operatorIdentity,
        grants: Object.entries(selected).filter(([, values]) => values.length).map(([id, values]) => ({ agent_instance_id: id, actions: values })),
        ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}), idempotency_key: crypto.randomUUID(), reason: reason.trim() };
      setPlan(await api.previewEnrollmentPermission(next)); setCommand(next);
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.approveEnrollmentPermission({ ...command, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="入驻审批预览"><div className="card-heading"><h3>审批 {item.username} 的入驻申请</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    {error && <p role="alert" className="form-error">{error}</p>}
    <form className="form" onSubmit={preview}>
      <p>批准后激活账号并加入申请的工作空间。岗位和 Agent 权限可在本次审批中选择，也可之后单独办理。</p>
      <label><input type="checkbox" checked={operatorIdentity} disabled={busy} onChange={event => { setOperatorIdentity(event.target.checked); setSelected({}); setPlan(null); }}/>同时赋予业务操作员身份</label>
      {operatorIdentity && candidates.map(agent => <fieldset key={agent.installation_id}><legend>{installationName(agent)}</legend>{actions.map(action => <label key={action} title={action}><input type="checkbox" disabled={busy} checked={selected[agent.installation_id]?.includes(action) || false} onChange={event => { setPlan(null); setSelected(current => { const values = current[agent.installation_id] || []; return { ...current, [agent.installation_id]: event.target.checked ? [...values, action] : values.filter(value => value !== action) }; }); }}/>{actionName(action)}</label>)}<TechnicalDetails values={{ "智能体安装编号": agent.installation_id }}/></fieldset>)}
      <label>成员、岗位与资源到期时间（留空为长期）<input type="datetime-local" value={expiresAt} disabled={busy} onChange={event => { setExpiresAt(event.target.value); setPlan(null); }}/></label>
      <label>审批理由<textarea required maxLength={500} value={reason} disabled={busy} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
      <button className="button primary" disabled={busy} type="submit">预览批准范围</button>
    </form>
    {plan && <div><p>激活 {item.username}，加入 {scopeLabel(asItems(plan.expanded_memberships)[0]?.scope)}。</p><ul>{asItems(plan.expanded_role_bindings).map(binding => <li key={binding.id}>岗位：{roleName(binding.role_code)}（版本 {binding.role_version}）</li>)}{asItems(plan.expanded_resource_grants).map(grant => <li key={grant.id}>{resourceName(grant.resource_type || "agent_installation", grant.resource_id, catalog)} · {actionName(grant.action)} · 本人数据<TechnicalDetails values={{ "资源编号": grant.resource_id, "操作代码": grant.action }}/></li>)}</ul>{!asItems(plan.expanded_resource_grants).length && <p>本次不授予智能体使用权限。</p>}<button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>确认批准并激活</button></div>}
  </section></Localized>;
}
