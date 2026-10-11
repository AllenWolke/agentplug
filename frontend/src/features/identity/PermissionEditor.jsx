import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { ResourceGrantEditor } from "./ResourceGrantEditor.jsx";
import { actionName, roleName, resourceName, installationName, dataScopeName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { administrationKind, isProtectedAdministratorBinding } from "./administration-state.js";
import { latestPresets, grantScopes, delegatedAgentTargets, effectiveAccess } from "./organization-access.js";
import { AuthorizationRevocations } from "./AuthorizationRevocations.jsx";

export function PermissionEditor({ user, principal, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [profile, setProfile] = useState(null);
  const protectedTarget = administrationKind(user) !== "platform" && (profile?.role_bindings || []).some(item => effectiveAccess(item) && isProtectedAdministratorBinding(item));
  const canChange = user?.capabilities?.includes("authorization.change") && principal.id !== user.username && !protectedTarget;
  const [presets, setPresets] = useState([]);
  const [workspaces, setWorkspaces] = useState([]);
  const [owner, setOwner] = useState(null);
  const [presetCode, setPresetCode] = useState("operator");
  const [scopeIndex, setScopeIndex] = useState("");
  const [installations, setInstallations] = useState([]);
  const [resourceIDs, setResourceIDs] = useState([]);
  const [revokeBindings, setRevokeBindings] = useState([]);
  const [revokeGrants, setRevokeGrants] = useState([]);
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const preset = presets.find(item => item.preset_code === presetCode);
  const scopes = useMemo(() => grantScopes(profile, preset, workspaces), [profile, preset, workspaces]);
  const scope = scopeIndex === "" ? undefined : scopes[Number(scopeIndex)]?.scope;

  useEffect(() => {
    let active = true;
    setProfile(null); setPlan(null); setError("");
    Promise.all([api.identityAccessProfile(principal.id), api.identityPresets(), api.identityWorkspaces(), api.identityAccessProfile(user.username)]).then(([nextProfile, nextPresets, workspaceResponse, owner]) => {
      if (!active) return;
      setProfile(nextProfile);
      const values = asItems(nextPresets).filter(item => !item.appointment_only && item.subject_type === "user");
      setPresets(latestPresets(administrationKind(user) === "department" ? values.filter(item => ["operator", "skill_user", "agent_delegate"].includes(item.preset_code)) : values));
      setWorkspaces(workspaceResponse.administration_workspaces || []);
      setOwner(owner);
    }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [principal.id]);

  useEffect(() => { setPlan(null); setScopeIndex(""); setResourceIDs([]); }, [presetCode]);
  useEffect(() => {
    let active = true;
    setPlan(null); setResourceIDs([]); setInstallations([]); setRevokeBindings([]); setRevokeGrants([]);
    if (!scope || !scope.application_id) return () => { active = false; };
    Promise.all([api.identityInstallationTargets({ tenant_id: scope.tenant_id, department_id: scope.department_id, application_id: scope.application_id }, "authorization"),
      administrationKind(user) === "department" ? api.departmentAgentPolicy({ tenant_id: scope.tenant_id, department_id: scope.department_id }) : Promise.resolve(null)])
      .then(([value, policy]) => { if (active) setInstallations(delegatedAgentTargets({ ...user, delegations: owner?.delegations || [], department_agent_policy: policy }, asItems(value).filter(item => ["active", "provisioning"].includes(item.status)), scope)); })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [scope, owner]);

  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      const command = {
        subject_type: "user", subject_id: principal.id,
        expected_revision: profile.principal.revision,
        idempotency_key: crypto.randomUUID(), reason: reason.trim(),
        revoke_binding_ids: revokeBindings, revoke_grant_ids: revokeGrants,
        preset: { preset_code: preset.preset_code, preset_version: preset.preset_version, scope,
          resource_ids: resourceIDs, ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}) }
      };
      setPlan(await api.previewIdentityAuthorization(command));
    } catch (cause) { setError(cause.message || "无法生成权限变更预览"); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.commitIdentityAuthorization({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      await onSaved(receipt); onClose();
    } catch (cause) {
      setError(cause.message || "授权办理失败");
      if (cause.status === 409) setPlan(null);
    } finally { setBusy(false); }
  };

  return <Localized><section className="card" aria-label="用户身份与权限配置">
    <div className="card-heading"><h3>为 {principal.id} 配置身份与权限</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    {error && <div className="form-error" role="alert">{error}</div>}
    {!profile ? <p>正在读取用户权限…</p> : profile.policy_mode !== "v2" ? <p>此账号尚未完成权限升级，暂不能办理岗位变更。</p> : <>
      {!canChange && <p>当前身份只能查看权限，不能办理变更。</p>}
      {protectedTarget && <p>此账号包含受保护的管理员身份，请由全平台管理员办理变更。</p>}
      <form className="form authorization-form" onSubmit={preview}><fieldset className="authorization-fields" disabled={busy || !canChange}>
        <label>岗位身份<select value={presetCode} onChange={event => setPresetCode(event.target.value)} disabled={busy}>{presets.map(item => <option key={`${item.preset_code}:${item.preset_version}`} value={item.preset_code}>{item.name}</option>)}</select></label>
        <label>部门与 Agent 接入范围<select required value={scopeIndex} disabled={busy} onChange={event => setScopeIndex(event.target.value)}><option value="">请选择</option>{scopes.map((item, index) => <option key={JSON.stringify(item.scope)} value={index} title={JSON.stringify(item.scope)}>{scopeLabel(item.scope)}</option>)}</select></label>
        {!scopes.length && <p>请先配置适用于该岗位的组织成员关系。</p>}
        {scope && <AuthorizationRevocations roles={(profile.role_bindings || []).filter(item => item.status === "active" && !isProtectedAdministratorBinding(item) && JSON.stringify(item.scope) === JSON.stringify(scope))} grants={(profile.resource_grants || []).filter(item => item.status === "active" && item.tenant_id === scope.tenant_id && item.department_id === scope.department_id && item.application_id === scope.application_id)} catalog={installations} selectedRoles={revokeBindings} selectedGrants={revokeGrants} disabled={busy} onRolesChange={values => { setRevokeBindings(values); setPlan(null); }} onGrantsChange={values => { setRevokeGrants(values); setPlan(null); }}/>} 
        {scope && <TechnicalDetails values={{ "组织与应用范围": scope }}/>} 
        {scope && preset?.resource_actions?.length > 0 && <fieldset><legend>允许使用的智能体（可不选，仅配置身份）</legend><div className="authorization-agent-options">{installations.map(item => <div className="authorization-agent-option" key={item.id}><label className="checkbox-field"><input type="checkbox" checked={resourceIDs.includes(item.id)} disabled={busy} onChange={event => { setPlan(null); setResourceIDs(current => event.target.checked ? [...current, item.id] : current.filter(id => id !== item.id)); }}/>{installationName(item)}</label><TechnicalDetails values={{ "安装编号": item.id, "智能体编号": item.agent_id }}/></div>)}</div></fieldset>}
        <label>到期时间（留空表示长期，须符合管理员授权范围）<input type="datetime-local" value={expiresAt} disabled={busy} onChange={event => { setExpiresAt(event.target.value); setPlan(null); }}/></label>
        <label>办理原因<textarea required maxLength={1000} value={reason} disabled={busy} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
        <button className="button primary" disabled={busy || !scope || !reason.trim()} type="submit">预览权限差异</button>
      </fieldset></form>
      {plan && <div aria-label="权限变更预览"><h4>本次新增</h4><ul>{asItems(plan.expanded_role_bindings).map(item => <li key={item.id}>{roleName(item)} · {scopeLabel(item.scope)}</li>)}{asItems(plan.expanded_resource_grants).map(item => <li key={item.id}>{resourceName(item.resource_type, item.resource_id, installations)} · {actionName(item.action)} · {dataScopeName(item.data_scope.type)}<TechnicalDetails values={{ "资源编号": item.resource_id, "操作代码": item.action }}/></li>)}</ul><h4>本次撤销</h4><ul>{(plan.change.revoke_binding_ids || []).map(id => <li key={id}>岗位：{roleName(profile.role_bindings.find(item => item.id === id))}<TechnicalDetails values={{ "岗位授权编号": id }}/></li>)}{(plan.change.revoke_grant_ids || []).map(id => <li key={id}>资源权限：{actionName(profile.resource_grants.find(item => item.id === id)?.action)}<TechnicalDetails values={{ "授权编号": id }}/></li>)}</ul><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>提交本次变更</button></div>}
      {canChange && <details className="advanced-permission-panel"><summary>高级设置：独立资源与精细权限</summary><p>模型、知识库、工具、技能及数据范围可在此单独调整。</p><ResourceGrantEditor user={user} profile={profile} onRefresh={async () => setProfile(await api.identityAccessProfile(principal.id))} onSaved={async receipt => { await onSaved(receipt); setProfile(await api.identityAccessProfile(principal.id)); }}/></details>}
    </>}
  </section></Localized>;
}
