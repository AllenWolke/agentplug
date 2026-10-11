import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { formatTime } from "../../format.js";
import { actionName, actionOption, resourceTypeName, resourceName, installationName, dataScopeName, sourceName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { delegatedAgentTargets } from "./organization-access.js";
import { administrationKind } from "./administration-state.js";
import { AuthorizationRevocations } from "./AuthorizationRevocations.jsx";

export function ResourceGrantEditor({ user, profile, onSaved, onRefresh }) {
  useLanguage();
  const [actions, setActions] = useState([]), [installations, setInstallations] = useState([]);
  const [plan, setPlan] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [action, setAction] = useState(""), [dataType, setDataType] = useState("owner"), [loading, setLoading] = useState(true);
  const [revokeIDs, setRevokeIDs] = useState([]);
  const scopeLabel = useScopeName();
  const definition = actions.find(item => item.code === action);
  const scope = { tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id };
  useEffect(() => { setPlan(null); setRevokeIDs([]); }, [profile.principal.id, profile.principal.revision, user.tenant_id, user.department_id, user.application_id]);
  useEffect(() => { let active = true;
    setLoading(true); setError(""); setActions([]); setInstallations([]); setAction(""); setPlan(null);
    Promise.all([api.identityPermissionActions(), api.identityInstallationTargets(scope, "authorization"), api.identityAccessProfile(user.username),
      administrationKind(user) === "department" ? api.departmentAgentPolicy({ tenant_id: scope.tenant_id, department_id: scope.department_id }) : Promise.resolve(null)])
      .then(([directory, catalog, owner, policy]) => { if (active) { setActions(asItems(directory).filter(item => !item.management)); setInstallations(delegatedAgentTargets({ ...user, delegations: owner.delegations, department_agent_policy: policy }, asItems(catalog).filter(item => ["active", "provisioning"].includes(item.status)), scope)); } }).catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user.tenant_id, user.department_id, user.application_id]);
  const preview = async event => { event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try { const values = new FormData(event.currentTarget), key = crypto.randomUUID(), definition = actions.find(item => item.code === values.get("action"));
      const installation = values.get("installation_id"), type = values.get("data_type");
      const grants = definition ? [{ id: "grant-" + key, ...scope, agent_instance_id: installation, subject_type: profile.principal.type, subject_id: profile.principal.id,
        action: definition.code, resource_type: definition.resource_type, resource_id: definition.resource_type === "agent_installation" ? installation : values.get("resource_id").trim(),
        effect: "allow", status: "active", revision: 1, source_id: "resource-editor:" + key,
        data_scope: { type, ...(type === "explicit_set" ? { ids: values.get("data_ids").split(/[\s,;]+/).filter(Boolean) } : {}) },
        ...(values.get("expires_at") ? { expires_at: new Date(values.get("expires_at")).toISOString() } : {}) }] : [];
      setPlan(await api.previewIdentityAuthorization({ subject_type: profile.principal.type, subject_id: profile.principal.id, expected_revision: profile.principal.revision,
        idempotency_key: key, reason: values.get("reason").trim(), resource_grants: grants, revoke_grant_ids: revokeIDs }));
    } catch (cause) { setError(cause.message); } finally { setBusy(false); }
  };
  const commit = async () => { setBusy(true); setError("");
    try { const receipt = await api.commitIdentityAuthorization({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at }); setPlan(null); await onSaved(receipt); }
    catch (cause) {
      setError(cause.message);
      if (cause.status === 409) {
        setPlan(null);
        try { await onRefresh?.(); setError("用户权限已被其他操作修改，已重新读取当前权限，请重新预览。"); }
        catch (refreshError) { setError("当前权限读取失败，请刷新后重试：" + refreshError.message); }
      }
    } finally { setBusy(false); }
  };
  const existingGrants = asItems(profile.resource_grants).filter(g => g.status === "active" && g.tenant_id === user.tenant_id && g.department_id === user.department_id && g.application_id === user.application_id);
  return <Localized><section className="card" aria-label="明确资源授权"><h3>办理独立资源权限</h3><p>目标账号：{profile.principal.id} · 工作空间：{scopeLabel(scope)}。资源使用权限需单独办理。</p>{error && <p role="alert">{error}</p>}
    <form className="form" onSubmit={preview} onChange={() => setPlan(null)}><fieldset disabled={busy || loading}><legend>新增资源授权</legend>
      <label>允许执行的操作<select name="action" value={action} onChange={event => setAction(event.target.value)}><option value="">仅撤销选中授权</option>{[...new Set(actions.map(item => item.resource_type))].map(type => <optgroup key={type} label={resourceTypeName(type)}>{actions.filter(item => item.resource_type === type).map(item => <option key={item.code} value={item.code} title={item.code}>{actionOption(item)}</option>)}</optgroup>)}</select></label>
      {definition && <>
        <label>使用资源的智能体<select name="installation_id" required><option value="">请选择智能体</option>{installations.map(item => <option key={item.id} value={item.id} title={item.id}>{installationName(item)}</option>)}</select></label>
        {!installations.length && <p className="form-hint">当前工作空间没有可授权的智能体。请切换到目标应用，或先为该应用安装智能体。</p>}
        {definition.resource_type !== "agent_installation" && <label>{resourceTypeName(definition.resource_type)}编号<input name="resource_id" required maxLength={128}/><small>填写该智能体实际使用的{resourceTypeName(definition.resource_type)}编号，由平台验证资源归属。</small></label>}
        <TechnicalDetails values={{ "操作代码": definition.code, "资源类型代码": definition.resource_type }}/>
        <label>数据范围<select name="data_type" value={dataType} onChange={event => setDataType(event.target.value)}><option value="owner">本人数据</option><option value="assigned_task">分配事项</option><option value="explicit_set">明确记录集合</option><option value="approved_organization">已授权组织</option></select></label>
        {dataType === "explicit_set" && <label>明确记录编号（每行一个）<textarea name="data_ids" required/></label>}<label>到期时间<input type="datetime-local" name="expires_at"/></label>
      </>}
      </fieldset><fieldset disabled={busy || loading}><legend>已有资源与办理原因</legend><AuthorizationRevocations grants={existingGrants} catalog={installations} selectedGrants={revokeIDs} disabled={busy || loading} onGrantsChange={values => { setRevokeIDs(values); setPlan(null); }}/>
      <label>办理原因<textarea required maxLength={1000} name="reason"/></label><button className="button primary" type="submit">预览资源权限差异</button></fieldset></form>
    {plan && <div aria-label="资源权限变更预览"><ul>{asItems(plan.expanded_resource_grants).map(g => <li key={g.id}>新增 {resourceName(g.resource_type, g.resource_id, installations)} · {actionName(g.action)} · {dataScopeName(g.data_scope.type)} · {g.expires_at ? formatTime(g.expires_at) + " 到期" : "长期"}<TechnicalDetails values={{ "资源编号": g.resource_id, "操作代码": g.action, "授权来源": g.source_id }}/></li>)}{asItems(plan.change.revoke_grant_ids).map(id => { const grant = asItems(profile.resource_grants).find(item => item.id === id); return <li key={id}>撤销 {grant ? `${resourceName(grant.resource_type, grant.resource_id, installations)} · ${actionName(grant.action)}` : "选中的授权"}<TechnicalDetails values={{ "授权编号": id }}/></li>; })}</ul><p>{plan.change.reason}</p><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>提交资源权限变更</button></div>}
  </section></Localized>;
}
