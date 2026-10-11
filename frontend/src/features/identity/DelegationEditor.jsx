import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { FreshAuthentication } from "./FreshAuthentication.jsx";
import { actionName, actionOption, installationName, resourceName } from "../../presentation.js";
import { useScopeName, TechnicalDetails } from "../../components/DisplayNames.jsx";
import { shortId } from "../../format.js";
import { grantScopes } from "./organization-access.js";

const managementOptions = [["authorization.change", "办理角色与资源授权"], ["access_request.decide", "审批权限申请"], ["membership.manage", "办理成员关系"], ["principal.disable", "停用普通账号"]];
const dataOptions = [["owner", "本人数据"], ["assigned_task", "指派任务"], ["explicit_set", "明确事项集合"], ["approved_organization", "批准的组织范围"]];
const effective = item => item.status === "active" && (!item.starts_at || Date.parse(item.starts_at) <= Date.now()) && (!item.expires_at || Date.now() < Date.parse(item.expires_at));
const contains = (outer, inner) => ["tenant_id", "department_id", "application_id", "resource_id"].every(key => !outer[key] || outer[key] === inner[key]);

export function DelegationEditor({ principal, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [profile, setProfile] = useState(null), [roles, setRoles] = useState([]), [actions, setActions] = useState([]);
  const [workspaces, setWorkspaces] = useState([]);
  const [installations, setInstallations] = useState([]), [scopeIndex, setScopeIndex] = useState("");
  const [selectedRoles, setSelectedRoles] = useState([]), [selectedActions, setSelectedActions] = useState([]);
  const [resources, setResources] = useState([]), [dataTypes, setDataTypes] = useState([]), [dataIDs, setDataIDs] = useState("");
  const [management, setManagement] = useState([]), [days, setDays] = useState("1"), [permanent, setPermanent] = useState(false);
  const [expires, setExpires] = useState(""), [reason, setReason] = useState(""), [revokeID, setRevokeID] = useState("");
  const [mode, setMode] = useState("create"), [plan, setPlan] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const scopes = grantScopes(profile, { scope_types: ["tenant", "department", "application"] }, workspaces).filter(member =>
    (profile?.role_bindings || []).some(binding => (binding.role_code === "permission_admin" || binding.role_code === "department_admin" && Number(binding.role_version) === 2) && effective(binding) && contains(binding.scope, member.scope)));
  const scope = scopeIndex === "" ? null : scopes[Number(scopeIndex)]?.scope;
  useEffect(() => {
    let active = true;
    Promise.all([api.identityAccessProfile(principal.id), api.identityRoleDefinitions(), api.identityPermissionActions(), api.identityWorkspaces()]).then(([p, r, a, spaces]) => {
      if (!active) return;
      setProfile(p); setRoles(asItems(r).filter(item => item.assignable && !["super_admin", "permission_admin"].includes(item.role_code)));
      setWorkspaces(spaces.administration_workspaces || []);
      setActions(asItems(a).filter(item => !item.management && item.resource_type === "agent_installation"));
    }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [principal.id]);
  useEffect(() => {
    let active = true;
    setInstallations([]); setResources([]); setPlan(null);
    if (scope?.application_id) api.identityInstallationTargets({ tenant_id: scope.tenant_id, department_id: scope.department_id, application_id: scope.application_id }, "delegation")
      .then(value => { if (active) setInstallations(asItems(value).filter(item => item.status === "active")); })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [scopeIndex, profile]);
  const change = setter => event => { setter(event.target.value); setPlan(null); };
  const toggle = (setter, value) => event => { setter(current => event.target.checked ? [...current, value] : current.filter(item => item !== value)); setPlan(null); };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      if (!profile?.principal?.revision) throw new Error("请重新读取用户当前版本");
      const command = { subject_id: principal.id, expected_revision: profile.principal.revision, idempotency_key: crypto.randomUUID(), reason: reason.trim() };
      if (mode === "revoke") {
        if (!revokeID) throw new Error("请选择需要撤销的委托");
        command.revoke_delegation_id = revokeID;
      } else {
        if (!scope) throw new Error("请选择当前权限管理员身份覆盖的成员范围");
        if (!management.length) throw new Error("请选择允许办理的管理操作");
        if (selectedActions.length && (!scope.application_id || !resources.length || !dataTypes.length)) throw new Error("业务授权委托必须选择应用、安装实例与数据范围");
        const ids = dataTypes.includes("explicit_set") ? [...new Set(dataIDs.split(/[\s,，]+/).filter(Boolean))] : [];
        if (dataTypes.includes("explicit_set") && !ids.length) throw new Error("请明确填写事项 ID");
        if (ids.length > 100) throw new Error("单次委托最多包含 100 个事项 ID");
        const seconds = Number(days) * 86400;
        if (!Number.isSafeInteger(seconds) || seconds <= 0 || seconds > 3650 * 86400) throw new Error("授权期限上限须为 1～3650 天");
        command.delegation = { id: crypto.randomUUID(), subject_id: principal.id, scope, roles: selectedRoles, actions: selectedActions, resources,
          data_scope_types: dataTypes, data_ids: ids, management_actions: management, max_duration_seconds: seconds, allow_permanent: permanent, status: "active", revision: 1,
          ...(!permanent && expires ? { expires_at: new Date(expires).toISOString() } : {}) };
      }
      setPlan(await api.previewIdentityDelegation(command));
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async proof => {
    setError("");
    try {
      const receipt = await api.changeIdentityDelegation({ ...plan.change, step_up_token: proof.step_up_token });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); throw cause; }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="授权委托办理">
    <div className="card-heading"><h3>授权委托 · {principal.id}</h3><button className="button secondary" onClick={onClose} disabled={busy}>关闭</button></div>
    <p>由公司管理员确定部门管理员或权限管理员可分配的 Agent、操作和期限。委托不会给予管理员本人业务使用权限。</p>
    {error && <div className="form-error" role="alert">{error}</div>}
    {!profile ? <p>正在读取当前身份…</p> : profile.policy_mode !== "v2" ? <p>此账号尚未完成权限升级。</p> : <>
      <form onSubmit={preview}>
        <label>办理类型<select value={mode} disabled={busy} onChange={change(setMode)}><option value="create">新增明确委托</option><option value="revoke">撤销已有委托</option></select></label>
        {mode === "revoke" ? <label>已有委托<select required value={revokeID} disabled={busy} onChange={change(setRevokeID)}><option value="">请选择</option>{(profile.delegations || []).filter(item => item.status === "active").map(item => <option key={item.id} value={item.id} title={item.id}>{scopeLabel(item.scope)} · 委托编号 {shortId(item.id)}</option>)}</select></label> : <>
          <label>委托组织范围<select required value={scopeIndex} disabled={busy} onChange={change(setScopeIndex)}><option value="">请选择</option>{scopes.map((member, index) => <option key={member.id} value={index}>{scopeLabel(member.scope)}</option>)}</select></label>
          {!scopes.length && <p>请先为该用户任命权限管理员身份，并建立对应成员关系。</p>}
          <fieldset><legend>允许办理的管理操作</legend>{managementOptions.map(([code, name]) => <label key={code}><input type="checkbox" disabled={busy} checked={management.includes(code)} onChange={toggle(setManagement, code)}/>{name}</label>)}</fieldset>
          <fieldset><legend>可授予的业务角色</legend>{roles.map(role => <label key={`${role.role_code}:${role.role_version}`}><input type="checkbox" disabled={busy} checked={selectedRoles.includes(role.role_code)} onChange={toggle(setSelectedRoles, role.role_code)}/>{role.name} · 版本 {role.role_version}</label>)}</fieldset>
          <fieldset><legend>可授权的业务操作</legend>{actions.map(action => <label key={action.code} title={action.code}><input type="checkbox" disabled={busy} checked={selectedActions.includes(action.code)} onChange={toggle(setSelectedActions, action.code)}/>{actionOption(action)}</label>)}</fieldset>
          <fieldset><legend>允许授权的智能体</legend>{!scope?.application_id ? <p>选择具体应用后可限定安装实例。</p> : installations.map(item => <label key={item.id} title={item.id}><input type="checkbox" disabled={busy} checked={resources.includes(item.id)} onChange={toggle(setResources, item.id)}/>{installationName(item)}</label>)}</fieldset>
          <fieldset><legend>允许授权的数据范围</legend>{dataOptions.map(([code, name]) => <label key={code}><input type="checkbox" disabled={busy} checked={dataTypes.includes(code)} onChange={toggle(setDataTypes, code)}/>{name}</label>)}</fieldset>
          {dataTypes.includes("explicit_set") && <label>明确事项 ID（逗号或空白分隔）<textarea required value={dataIDs} disabled={busy} onChange={change(setDataIDs)}/></label>}
          <label>可授予权限的最长天数<input type="number" min="1" max="3650" step="1" required value={days} disabled={busy} onChange={change(setDays)}/></label>
          <label><input type="checkbox" checked={permanent} disabled={busy} onChange={event => { setPermanent(event.target.checked); setExpires(""); setPlan(null); }}/>允许授予长期权限（委托自身须长期有效）</label>
          {!permanent && <label>委托自身到期时间（留空为长期）<input type="datetime-local" value={expires} disabled={busy} onChange={change(setExpires)}/></label>}
        </>}
        <label>办理原因<textarea value={reason} required maxLength={2000} disabled={busy} onChange={change(setReason)}/></label>
        <button className="button primary" disabled={busy || !reason.trim()}>预览委托变更</button>
      </form>
      {plan && <><h4>委托变更预览</h4>{plan.change.delegation ? <dl>
        <dt>办理范围</dt><dd>{scopeLabel(plan.change.delegation.scope)}</dd>
        <dt>管理操作</dt><dd>{plan.change.delegation.management_actions.map(code => managementOptions.find(item => item[0] === code)?.[1] || code).join("、")}</dd>
        <dt>可授予角色</dt><dd>{plan.change.delegation.roles.map(code => roles.find(item => item.role_code === code)?.name || code).join("、") || "无"}</dd>
        <dt>可授权业务操作</dt><dd>{plan.change.delegation.actions.map(actionName).join("、") || "无"}</dd>
        <dt>允许使用的智能体</dt><dd>{plan.change.delegation.resources.map(id => resourceName("agent_installation", id, installations)).join("、") || "无"}</dd>
        <dt>数据范围</dt><dd>{plan.change.delegation.data_scope_types.map(code => dataOptions.find(item => item[0] === code)?.[1] || code).join("、") || "无"}</dd>
        {plan.change.delegation.data_ids?.length > 0 && <><dt>明确事项</dt><dd>{plan.change.delegation.data_ids.join("、")}</dd></>}
        <dt>授权期限上限</dt><dd>{plan.change.delegation.max_duration_seconds / 86400} 天{plan.change.delegation.allow_permanent ? "，可授予长期权限" : ""}</dd>
        <dt>委托到期</dt><dd>{plan.change.delegation.expires_at ? new Date(plan.change.delegation.expires_at).toLocaleString() : "长期有效"}</dd>
      </dl> : <p>撤销所选委托，其后该来源不能继续办理授权。</p>}<TechnicalDetails values={{ "委托变更": plan.change.delegation || plan.change.revoke_delegation_id }}/><p>原因：{plan.change.reason}</p><FreshAuthentication key={plan.request_digest} action={plan.step_up_action} requestDigest={plan.request_digest} onProof={commit} onBusy={setBusy}/></>}
    </>}
  </section></Localized>;
}
