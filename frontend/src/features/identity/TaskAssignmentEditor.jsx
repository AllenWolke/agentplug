import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { actionName, installationName, resourceName } from "../../presentation.js";
import { formatTime } from "../../format.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";

export function TaskAssignmentEditor({ principal, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [profile, setProfile] = useState(null);
  const [installations, setInstallations] = useState([]);
  const [scopeIndex, setScopeIndex] = useState("");
  const [installationID, setInstallationID] = useState("");
  const [taskID, setTaskID] = useState("");
  const [action, setAction] = useState("business.content.read");
  const [expiresAt, setExpiresAt] = useState("");
  const [revokes, setRevokes] = useState([]);
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const scopes = (profile?.memberships || []).filter(item => item.status === "active" && item.scope.scope_type === "application" && (!item.starts_at || Date.parse(item.starts_at) <= Date.now()) && (!item.expires_at || Date.parse(item.expires_at) > Date.now()));
  const scope = scopeIndex === "" ? undefined : scopes[Number(scopeIndex)]?.scope;
  useEffect(() => {
    let active = true;
    api.identityAccessProfile(principal.id).then(value => { if (active) setProfile(value); }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [principal.id]);
  useEffect(() => {
    let active = true;
    setInstallationID(""); setInstallations([]); setPlan(null);
    if (scope) api.identityInstallationTargets({ tenant_id: scope.tenant_id, department_id: scope.department_id, application_id: scope.application_id }, "authorization").then(value => { if (active) setInstallations(asItems(value).filter(item => item.status === "active")); }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [scope]);
  const change = setter => event => { setter(event.target.value); setPlan(null); };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      const key = crypto.randomUUID();
      const assignments = taskID.trim() ? [{ id: `assignment-${key}`, subject_id: principal.id, task_id: taskID.trim(), action,
        scope: { ...scope, scope_type: "agent_installation", resource_id: installationID }, status: "active", revision: 1, source_id: key,
        ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}) }] : [];
      setPlan(await api.previewIdentityAuthorization({ subject_type: "user", subject_id: principal.id, expected_revision: profile.principal.revision,
        idempotency_key: key, reason: reason.trim(), task_assignments: assignments, revoke_assignment_ids: revokes }));
    } catch (cause) { setError(cause.message || "指派预览失败"); } finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.commitIdentityAuthorization({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message || "指派提交失败"); if (cause.status === 409) setPlan(null); } finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="任务指派管理">
    <div className="card-heading"><h3>为 {principal.id} 指派任务</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    <p>指派只决定相应操作的任务范围。用户还需具备岗位与 Agent 资源权限；撤销指派后，该来源的访问将失效。</p>
    {error && <div className="form-error" role="alert">{error}</div>}
    {!profile ? <p>正在读取指派记录…</p> : profile.policy_mode !== "v2" ? <p>请先完成此账号的权限升级。</p> : <>
      <form onSubmit={preview}>
        <label>应用范围<select disabled={busy} value={scopeIndex} onChange={change(setScopeIndex)}><option value="">请选择</option>{scopes.map((item, index) => <option key={item.id} value={index}>{scopeLabel(item.scope)}</option>)}</select></label>
        <label>允许使用的智能体<select disabled={busy} value={installationID} onChange={change(setInstallationID)}><option value="">请选择</option>{installations.map(item => <option key={item.id} value={item.id} title={item.id}>{installationName(item)}</option>)}</select></label>
        <label>新增指派的任务 ID（仅撤销时留空）<input disabled={busy} maxLength={128} value={taskID} onChange={change(setTaskID)}/></label>
        <label>指派操作<select disabled={busy} value={action} onChange={change(setAction)}><option value="business.content.read">读取业务内容</option><option value="business.review">审核业务内容</option><option value="history.read">读取历史</option><option value="cancel">取消执行</option></select></label>
        <label>到期时间<input disabled={busy} type="datetime-local" value={expiresAt} onChange={change(setExpiresAt)}/></label>
        <fieldset><legend>撤销已有指派</legend>{(profile.task_assignments || []).filter(item => item.status === "active").map(item => <div className="permission-record" key={item.id}><label><input disabled={busy} type="checkbox" checked={revokes.includes(item.id)} onChange={event => { setPlan(null); setRevokes(values => event.target.checked ? [...values, item.id] : values.filter(id => id !== item.id)); }}/>{actionName(item.action)} · {scopeLabel(item.scope)} · {item.expires_at ? formatTime(item.expires_at) : "长期有效"}</label><TechnicalDetails values={{ "指派编号": item.id, "业务任务编号": item.task_id, "智能体安装编号": item.scope.resource_id, "操作代码": item.action }}/></div>)}</fieldset>
        <label>办理原因<textarea required disabled={busy} maxLength={1000} value={reason} onChange={change(setReason)}/></label>
        <button className="button primary" disabled={busy || !reason.trim() || (!taskID.trim() && !revokes.length) || (Boolean(taskID.trim()) && (!scope || !installationID))}>预览指派变更</button>
      </form>
      {plan && <div aria-label="指派变更预览"><h4>新增指派</h4><ul>{(plan.expanded_task_assignments || []).map(item => <li key={item.id}>{actionName(item.action)} · {resourceName("agent_installation", item.scope.resource_id, installations)} · {item.expires_at ? formatTime(item.expires_at) : "长期有效"}<TechnicalDetails values={{ "业务任务编号": item.task_id, "任务归属用户": item.task_object?.owner_id, "智能体安装编号": item.scope.resource_id, "操作代码": item.action }}/></li>)}</ul><h4>撤销指派</h4><ul>{[...(plan.change.revoke_assignment_ids || []), ...(plan.automatic_revoke_assignment_ids || [])].map(id => { const record = profile.task_assignments?.find(item => item.id === id); return <li key={id}>{record ? `${actionName(record.action)} · ${scopeLabel(record.scope)}` : "撤销所选指派"}<TechnicalDetails values={{ "指派编号": id, "业务任务编号": record?.task_id }}/></li>; })}</ul><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>提交指派变更</button></div>}
    </>}
  </section></Localized>;
}
