import React, { useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { installationName, resourceTypeName } from "../../presentation.js";
import { administrationKind } from "./administration-state.js";
import { delegatedAgentTargets } from "./organization-access.js";
import { agentUseBatchCommand, loadBatchProfiles } from "./permission-batch.js";

export function AgentUseResources({ counts }) {
  return <p className="form-hint">{Object.entries(counts || {}).map(([type, count], index) => <React.Fragment key={type}>{index > 0 && " · "}<span>{resourceTypeName(type)}</span> <b>{count}</b></React.Fragment>)}</p>;
}

export function BatchAgentUseForm({ user, owner, workspaces, principals, onPreview, onBusyChange }) {
  useLanguage();
  const scopeLabel = useScopeName(workspaces);
  const apps = useMemo(() => workspaces.filter(item => item.tenant_id === user.tenant_id && item.application_id && item.management_actions?.includes("authorization.change")), [workspaces, user.tenant_id]);
  const departments = useMemo(() => [...new Map(apps.map(item => [item.department_id, item])).values()], [apps]);
  const [department, setDepartment] = useState(""), [app, setApp] = useState("");
  const [agents, setAgents] = useState([]), [installation, setInstallation] = useState("");
  const [cursor, setCursor] = useState(""), [next, setNext] = useState("");
  const [pack, setPack] = useState(null), [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(false), [packageLoading, setPackageLoading] = useState(false), [busy, setBusy] = useState(false);
  const [expiresAt, setExpiresAt] = useState(""), [reason, setReason] = useState(""), [error, setError] = useState("");
  const canJoin = user.capabilities?.includes("membership.manage");
  const [joinDepartment, setJoinDepartment] = useState(Boolean(canJoin));
  const departmentApps = apps.filter(item => item.department_id === department);
  const scope = { scope_type: "application", tenant_id: user.tenant_id, department_id: department, application_id: app };
  const selected = agents.find(item => item.id === installation);
  const counts = useMemo(() => {
    const result = {}, seen = new Set();
    for (const resource of pack?.resources || []) {
      const key = JSON.stringify([resource.resource_type, resource.resource_id]);
      if (!seen.has(key)) { seen.add(key); result[resource.resource_type] = (result[resource.resource_type] || 0) + 1; }
    }
    return result;
  }, [pack]);
  useEffect(() => { if (!department && departments.length === 1) setDepartment(departments[0].department_id); }, [departments, department]);
  useEffect(() => {
    setApp(""); setCursor(""); setNext(""); setInstallation(""); setPack(null); setError(""); onPreview(null);
    const values = apps.filter(item => item.department_id === department);
    if (values.length === 1) setApp(values[0].application_id);
  }, [department, apps]);
  useEffect(() => { onBusyChange(busy); return () => onBusyChange(false); }, [busy, onBusyChange]);
  useEffect(() => {
    let active = true;
    setAgents([]); setNext(""); setInstallation(""); setPack(null); setPolicy(null); setError(""); onPreview(null);
    if (!app || !department) { setLoading(false); return () => { active = false; }; }
    setLoading(true);
    Promise.all([api.identityInstallationTargets({ tenant_id: user.tenant_id, department_id: department, application_id: app }, "authorization", cursor),
      administrationKind(user) === "department" ? api.departmentAgentPolicy({ tenant_id: user.tenant_id, department_id: department }) : Promise.resolve(null)])
      .then(([value, ceiling]) => {
        if (!active) return;
        const values = delegatedAgentTargets({ ...user, delegations: owner?.delegations || [], department_agent_policy: ceiling }, asItems(value).filter(item => item.status === "active"), scope);
        setAgents(values); setNext(value.next_cursor || ""); setPolicy(ceiling);
      }).catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [app, department, cursor, user.tenant_id, owner]);
  useEffect(() => {
    let active = true;
    setPack(null); setError(""); onPreview(null);
    if (!installation) { setPackageLoading(false); return () => { active = false; }; }
    setPackageLoading(true);
    api.identityAgentUsePackage({ department_id: department, application_id: app, installation_id: installation })
      .then(value => { if (active) setPack(value); }).catch(cause => { if (active) setError(cause.message); })
      .finally(() => { if (active) setPackageLoading(false); });
    return () => { active = false; };
  }, [installation, app, department]);
  const invalidate = update => { update(); onPreview(null); };
  const submit = async event => {
    event.preventDefault(); if (busy || !pack) return;
    setBusy(true); setError(""); onPreview(null);
    try {
      const fresh = await api.identityAgentUsePackage({ department_id: department, application_id: app, installation_id: installation });
      if (fresh.package_digest !== pack.package_digest || fresh.agent_version_id !== pack.agent_version_id) {
        setPack(fresh); throw new Error("Agent 配置已变更，请核对更新后的说明并重新预览。");
      }
      const profiles = await loadBatchProfiles(api, principals.map(item => item.id));
      const command = agentUseBatchCommand({ user, principals, profiles, pack: fresh, joinDepartment: canJoin && joinDepartment, expiresAt, reason, key: crypto.randomUUID(), newID: () => `member-${crypto.randomUUID()}` });
      onPreview(await api.previewPermissionBatch(command));
    } catch (cause) { setError(cause.message || "无法生成批量变更预览。"); }
    finally { setBusy(false); }
  };
  return <Localized><section id="batch-agent-use-assignment" className="card" aria-label="批量开通 Agent 使用">
    <div className="card-heading"><h3>批量开通 Agent 使用</h3><span>已选 {principals.length} 位用户</span></div>
    <p>选择一个 Agent，一次开通所选用户的个人会话及已发布配置所需的模型、知识库、工具和记忆权限。</p>
    <p className="form-hint">分享、导出、内容修改和管理权限须另行配置。已有权限和拒绝规则会保留，拒绝规则仍优先生效。</p>
    <form className="form" onSubmit={submit}><fieldset disabled={busy}>
      <label>目标部门<select required value={department} onChange={event => setDepartment(event.target.value)}><option value="">请选择部门</option>{departments.map(item => <option key={item.department_id} value={item.department_id}>{item.department_name || scopeLabel({ scope_type: "department", tenant_id: item.tenant_id, department_id: item.department_id })}</option>)}</select></label>
      {departmentApps.length > 1 && <label>Agent 分组<select required value={app} onChange={event => { setCursor(""); setApp(event.target.value); }}><option value="">请选择 Agent 分组</option>{departmentApps.map(item => <option key={item.application_id} value={item.application_id}>{item.application_name || scopeLabel({ scope_type: "application", tenant_id: item.tenant_id, department_id: item.department_id, application_id: item.application_id })}</option>)}</select></label>}
      <label>可开通的 Agent<select id="batch-agent-use-target" required disabled={!app || loading} value={installation} onChange={event => setInstallation(event.target.value)}><option value="">{loading ? "正在读取 Agent…" : "请选择 Agent"}</option>{agents.map(item => <option key={item.id} value={item.id}>{installationName(item)}</option>)}</select></label>
      <div className="pagination-controls"><button className="button secondary" type="button" disabled={busy || loading || !cursor} onClick={() => setCursor("")}>返回第一页 Agent</button><button className="button secondary" type="button" disabled={busy || loading || !next} onClick={() => setCursor(next)}>下一页 Agent</button></div>
      {packageLoading && <p role="status">正在核对 Agent 依赖…</p>}
      {pack && <div className="plan-preview"><h4><span data-i18n-preserve>{installationName(selected || {})}</span><span> · 本次开通内容</span></h4><p>可查看、运行和取消 Agent，查看及继续自己的会话；依赖资源仅在该 Agent 范围内使用。</p><AgentUseResources counts={counts}/><TechnicalDetails values={{ "Agent 版本": pack.agent_version_id, "审核配置摘要": pack.package_digest, "依赖资源": pack.resources }}/></div>}
      {policy?.managed && <p className="form-hint">仍需满足公司为本部门批准的 Agent 操作和有效期；缺少必要依赖会在逐人预览中拒绝，不开通残缺权限。</p>}
      {canJoin ? <><label className="checkbox-field"><input type="checkbox" checked={joinDepartment} onChange={event => invalidate(() => setJoinDepartment(event.target.checked))}/><span>同步加入尚未加入该部门的用户</span></label><p className="form-hint">已有成员关系及期限保持不变。失效成员须先续期；预览会明确显示新增成员。</p></> : <p className="form-hint">当前身份仅可为已有成员开通 Agent。</p>}
      <label>统一到期时间（留空遵循当前授权范围）<input type="datetime-local" value={expiresAt} onChange={event => invalidate(() => setExpiresAt(event.target.value))}/></label>
      <label>共同办理原因<textarea required maxLength={1000} value={reason} onChange={event => invalidate(() => setReason(event.target.value))}/></label>
      <button className="button primary" disabled={busy || packageLoading || loading || !pack || !reason.trim()}>预览每人的变更</button>
    </fieldset></form>
    {!apps.length && <p className="notice">当前没有可管理的 Agent 范围，请联系公司管理员配置。</p>}
    {error && <p className="form-error" role="alert">{error}</p>}
  </section></Localized>;
}
