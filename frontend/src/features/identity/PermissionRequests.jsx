import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { administrationKind, canRequestOwnPermissions } from "./administration-state.js";
import { permissionRequestScopes } from "./workspace-state.js";
import { Link } from "react-router-dom";
import { asItems } from "../../state.js";
import { actionName, installationName, resourceName, roleName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { BatchRequestReview } from "./BatchRequestReview.jsx";
import { PERMISSION_BATCH_LIMIT, selectBatchRecords } from "./permission-batch.js";

const actions = { discover: "查看 Agent", run: "运行", "history.read": "查看历史", "history.continue": "继续会话", "history.revise": "修订", "history.regenerate": "重新生成", cancel: "取消运行", "history.share": "分享历史（敏感）", "history.export": "导出历史（敏感）", "history.delete.request": "申请删除历史" };
const outcomes = { pending: "待办理", approved: "已批准", rejected: "未批准", withdrawn: "已撤回" };
const basicActions = ["discover", "run", "cancel", "history.read", "history.continue"];

export function PermissionRequests({ user, review = false }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState(review ? "pending" : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [roles, setRoles] = useState([]);
  const [workspaces, setWorkspaces] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [scopeIndex, setScopeIndex] = useState("");
  const [roleCodes, setRoleCodes] = useState([]);
  const [resourceActions, setResourceActions] = useState({});
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [editing, setEditing] = useState(null);
  const [selected, setSelected] = useState([]);
  const [decisionReason, setDecisionReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [batchSelected, setBatchSelected] = useState([]);
  const [batchLocked, setBatchLocked] = useState(false);
  const batchSelectable = items.filter(item => item.status === "pending" && item.subject_id !== user.username);
  const selectBatch = (records, checked) => {
    if (batchLocked || busy) return;
    try { setBatchSelected(selectBatchRecords(batchSelected, records, checked)); setError(""); }
    catch (cause) { setError(cause.message); }
  };
  const pendingCreate = useRef(null);
  const scope = scopeIndex === "" ? undefined : workspaces[Number(scopeIndex)];
  const label = item => item.kind === "role" ? `岗位：${roles.find(role => role.role_code === item.role_code && role.role_version === item.role_version)?.name || roleName(item.role_code)}（版本 ${item.role_version}）` : `${resourceName("agent_installation", item.resource_id, catalog)} · ${actionName(item.action)}`;
  const reload = useCallback(async () => {
    const value = await api.permissionRequests({ view: review ? "review" : "mine", status, page, page_size: 20 });
    setItems(asItems(value)); setTotal(value.total);
  }, [review, status, page, user.tenant_id, user.department_id, user.application_id]);
  useEffect(() => { let active = true; reload().catch(cause => { if (active) setError(cause.message); }); return () => { active = false; }; }, [reload]);
  useEffect(() => {
    if (review || !canRequestOwnPermissions(user)) return;
    let active = true;
    Promise.all([api.identityRoleDefinitions(), api.identityWorkspaces(), api.myAgentCatalog()]).then(([nextRoles, nextScopes, nextCatalog]) => {
      if (!active) return;
      setRoles(asItems(nextRoles).filter(role => role.assignable && !["super_admin", "permission_admin"].includes(role.role_code)));
      setWorkspaces(permissionRequestScopes(nextScopes, user.tenant_id));
      setCatalog(asItems(nextCatalog));
    }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [review, user.tenant_id, user.department_id, user.application_id]);
  const create = async event => {
    event.preventDefault(); if (!canRequestOwnPermissions(user)) return; setBusy(true); setError("");
    try {
      const validity = expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {};
      const signature = JSON.stringify({ scope, roleCodes, resourceActions, reason: reason.trim(), expiresAt });
      const applicationScope = { scope_type: "application", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id };
      const requested = roleCodes.map(key => {
        const role = roles.find(role => `${role.role_code}:${role.role_version}` === key && role.scope_types.includes(scope.scope_type));
        if (!role) throw new Error("岗位配置已变更，请重新选择。");
        return { id: crypto.randomUUID(), kind: "role", scope, role_code: role.role_code, role_version: role.role_version, ...validity };
      });
      for (const [id, values] of Object.entries(resourceActions)) for (const action of values) requested.push({ id: crypto.randomUUID(), kind: "resource", scope: applicationScope, resource_id: id, action, data_scope: { type: "owner" }, ...validity });
      if (!pendingCreate.current || pendingCreate.current.signature !== signature) pendingCreate.current = { signature, command: { scope, items: requested, reason: reason.trim(), idempotency_key: crypto.randomUUID() } };
      await api.createPermissionRequest(pendingCreate.current.command);
      pendingCreate.current = null;
      setRoleCodes([]); setResourceActions({}); setReason(""); setNotice("申请已提交；提交申请不会产生权限。"); await reload();
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const withdraw = async item => {
    setBusy(true); setError("");
    try { await api.withdrawPermissionRequest({ request_id: item.id, expected_revision: item.revision, idempotency_key: crypto.randomUUID(), reason: "本人撤回申请" }); await reload(); }
    catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const beginReview = item => { setEditing(item); setSelected([]); setDecisionReason(""); setPlan(null); };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      const profile = await api.identityAccessProfile(editing.subject_id);
      setPlan(await api.previewPermissionRequestDecision({ request_id: editing.id, expected_revision: editing.revision,
        expected_subject_revision: profile.principal.revision, decision: selected.length ? "approved" : "rejected", approved_item_ids: selected,
        idempotency_key: crypto.randomUUID(), reason: decisionReason.trim() }));
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try { await api.decidePermissionRequest({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at }); setEditing(null); setPlan(null); setNotice("申请已办理，未勾选事项未获批准。"); await reload(); }
    catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); }
    finally { setBusy(false); }
  };
  const resourcesInScope = scope && scope.tenant_id === user.tenant_id && (!scope.department_id || scope.department_id === user.department_id) && (!scope.application_id || scope.application_id === user.application_id);
  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">申请与办理</p><h2>{review ? "角色与资源申请审批" : "我的权限申请"}</h2><p>申请不会立即开通权限。办理后可查看每项结果，未获批准的事项仍不可使用。</p></div></div>
    {error && <p role="alert" className="form-error">{error}</p>}{notice && <p role="status" className="success-banner">{notice}</p>}
    {review && batchLocked && <div className="notice"><span>批量操作正在处理或等待核对。</span><button className="text-button" onClick={() => document.getElementById("permission-batch-decision")?.scrollIntoView({ block: "start", behavior: "smooth" })}>查看批次结果</button></div>}
    {!review && administrationKind(user) && <section className="card"><h3>此账号用于管理</h3><p>管理员账号不能为自己新建权限申请或增加业务权限。请使用独立业务账号申请助手和资源权限，由其他有权管理员办理。</p><Link className="button secondary" to="/workspace/my-permissions">查看我的管理范围</Link></section>}
    {!review && canRequestOwnPermissions(user) && <section className="card"><h3>新建申请</h3><form className="form" aria-label="新建权限申请" onSubmit={create}>
      <label>申请范围<select required disabled={busy} value={scopeIndex} onChange={event => { setScopeIndex(event.target.value); setRoleCodes([]); setResourceActions({}); }}><option value="">请选择成员范围</option>{workspaces.map((value, index) => <option key={index} value={index} title={JSON.stringify(value)}>{scopeLabel(value)}</option>)}</select></label>
      {scopeIndex !== "" && <fieldset><legend>岗位身份</legend>{roles.filter(role => role.scope_types.includes(scope.scope_type)).map(role => {
        const key = `${role.role_code}:${role.role_version}`;
        return <label key={key}><input type="checkbox" name="role_code" value={key} disabled={busy} checked={roleCodes.includes(key)} onChange={event => setRoleCodes(current => event.target.checked ? [...current, key] : current.filter(value => value !== key))}/>{role.name}（版本 {role.role_version}）</label>;
      })}</fieldset>}
      {scopeIndex !== "" && resourcesInScope && catalog.map(agent => <fieldset key={agent.installation_id}><legend>{installationName(agent)}</legend><p className="form-hint">基础使用包括查看、运行、取消、查看本人历史和继续会话。分享、导出等能力需要单独核对。</p><div className="inline-actions"><button type="button" className="button secondary compact" disabled={busy} onClick={() => setResourceActions(current => ({ ...current, [agent.installation_id]: [...new Set([...(current[agent.installation_id] || []), ...basicActions])] }))}>选择基础使用 5 项</button><button type="button" className="text-button" disabled={busy} onClick={() => setResourceActions(current => ({ ...current, [agent.installation_id]: [] }))}>清空此助手</button></div>{Object.keys(actions).map(action => <label key={action} title={action}><input type="checkbox" name="resource_action" value={action} data-installation-id={agent.installation_id} disabled={busy} checked={resourceActions[agent.installation_id]?.includes(action) || false} onChange={event => setResourceActions(current => { const values = current[agent.installation_id] || []; return { ...current, [agent.installation_id]: event.target.checked ? [...values, action] : values.filter(value => value !== action) }; })}/>{actionName(action)}</label>)}<TechnicalDetails values={{ "智能体安装编号": agent.installation_id }}/></fieldset>)}
      <label>申请到期时间（留空为长期）<input type="datetime-local" disabled={busy} value={expiresAt} onChange={event => setExpiresAt(event.target.value)}/></label>
      <label>申请原因<textarea required maxLength={1000} disabled={busy} value={reason} onChange={event => setReason(event.target.value)}/></label>
      <button className="button primary" disabled={busy || scopeIndex === "" || !roleCodes.length && !Object.values(resourceActions).some(values => values.length)} type="submit">提交申请</button>
    </form></section>}
    <section className="card"><label>申请状态<select value={status} disabled={busy} onChange={event => { setStatus(event.target.value); setPage(1); }}><option value="">全部</option>{Object.entries(outcomes).map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select></label>
      {review && <div className="batch-selection-bar"><label className="checkbox-field"><input type="checkbox" disabled={busy || batchLocked || !batchSelectable.length} checked={batchSelectable.length > 0 && batchSelectable.every(item => batchSelected.some(value => value.id === item.id))} onChange={event => selectBatch(batchSelectable, event.target.checked)}/>选择本页待办理申请</label><span>跨页已选 {batchSelected.length} / {PERMISSION_BATCH_LIMIT} 份</span><button className="button secondary" disabled={batchLocked || busy || !batchSelected.length} onClick={() => document.getElementById("batch-request-review")?.scrollIntoView({ block: "start", behavior: "smooth" })}>核对所选申请</button><button className="text-button" disabled={batchLocked || busy || !batchSelected.length} onClick={() => setBatchSelected([])}>清空选择</button></div>}
      {!items.length && !error && <div className="empty"><b>{review ? "暂无待处理申请" : "暂无权限申请"}</b><p>{review ? "用户提交申请后，可在这里逐项审核。" : "选择申请范围、岗位或 Agent 操作，填写原因后提交。"}</p></div>}
      {items.map(item => <article key={item.id} className="permission-request-record"><h3>{review && <input type="checkbox" aria-label={`选择 ${item.subject_id} 的申请`} checked={batchSelected.some(value => value.id === item.id)} disabled={busy || batchLocked || item.status !== "pending" || item.subject_id === user.username} onChange={event => selectBatch([item], event.target.checked)}/>}<span data-i18n-preserve>{item.subject_id}</span> · {outcomes[item.status]}</h3><p data-i18n-preserve>{item.reason}</p><details><summary>查看申请事项（{item.items.length} 项）</summary><ul>{item.items.map(value => <li key={value.id}>{label(value)} · {outcomes[value.outcome]}<TechnicalDetails values={{ "申请事项编号": value.id, "资源编号": value.resource_id, "操作代码": value.action, "角色代码": value.role_code }}/></li>)}</ul></details>{item.comment && <p data-i18n-preserve>办理说明：{item.comment}</p>}{item.status === "pending" && (review ? <button className="button secondary" disabled={busy || batchLocked || item.subject_id === user.username} onClick={() => beginReview(item)}>核对与办理</button> : <button className="button secondary" disabled={busy} onClick={() => withdraw(item)}>撤回申请</button>)}</article>)}
      <div className="pagination-controls"><span>共 {total} 条 · 第 {page} 页</span><button className="button secondary" disabled={busy || page === 1} onClick={() => setPage(value => value - 1)}>上一页</button><button className="button secondary" disabled={busy || page * 20 >= total} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    </section>
    {review && <BatchRequestReview user={user} requests={batchSelected} label={label} onLockedChange={setBatchLocked} onClear={() => setBatchSelected([])}
      onSaved={async () => { setNotice("批次结果已保存，请按每份申请的结果核对。"); await reload(); }}/>} 
    {editing && <section className="card"><div className="card-heading"><h3>办理 {editing.subject_id} 的申请</h3><button className="button secondary" disabled={busy} onClick={() => { setEditing(null); setPlan(null); }}>关闭</button></div><form className="form" aria-label="逐项申请审批" onSubmit={preview}><fieldset><legend>选择本次批准事项</legend><p className="form-hint">未勾选事项将被拒绝；全部不勾选表示拒绝整份申请。基础使用快捷选择不会包含分享、导出或管理员权限。</p><div className="inline-actions"><button type="button" className="button secondary compact" disabled={busy} onClick={() => { setPlan(null); setSelected(current => [...new Set([...current, ...editing.items.filter(item => item.kind === "role" ? item.role_code === "operator" : basicActions.includes(item.action)).map(item => item.id)])]); }}>选择申请中的基础使用事项</button><button type="button" className="text-button" disabled={busy} onClick={() => { setPlan(null); setSelected([]); }}>清空批准事项</button></div>{editing.items.map(item => <label key={item.id}><input type="checkbox" name="approved_item_id" value={item.id} disabled={busy} checked={selected.includes(item.id)} onChange={event => { setPlan(null); setSelected(current => event.target.checked ? [...current, item.id] : current.filter(id => id !== item.id)); }}/>{label(item)}</label>)}</fieldset><label>办理原因<textarea required maxLength={1000} disabled={busy} value={decisionReason} onChange={event => { setDecisionReason(event.target.value); setPlan(null); }}/></label><button className="button primary" disabled={busy} type="submit">预览批准与拒绝结果</button></form>{plan && <div><ul>{plan.items.map(item => <li key={item.id}>{label(item)} · {outcomes[item.outcome]}</li>)}</ul><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>确认办理</button></div>}</section>}
  </></Localized>;
}
