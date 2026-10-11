import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { formatStatus, formatTime } from "../../format.js";
import { actionName, roleName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { effectiveAccess, membershipTargets } from "./organization-access.js";
import { canAssignDepartmentRoles, administrationKind, isProtectedAdministratorBinding } from "./administration-state.js";

export function MembershipEditor({ user, principal, preferredDepartmentID = "", onSaved, onClose }) {
  useLanguage();
  const [departmentNames, setDepartmentNames] = useState([]);
  const scopeLabel = useScopeName(departmentNames);
  const [profile, setProfile] = useState(null);
  const protectedTarget = administrationKind(user) !== "platform" && (profile?.role_bindings || []).some(item => effectiveAccess(item) && isProtectedAdministratorBinding(item));
  const [targets, setTargets] = useState([]);
  const [selected, setSelected] = useState("");
  const [departmentRole, setDepartmentRole] = useState("");
  const [status, setStatus] = useState("active");
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    Promise.all([api.identityAccessProfile(principal.id), api.identityWorkspaces(), api.identityAccessProfile(user.username)]).then(([value, workspaces, owner]) => { if (active) { setProfile(value); const names = [...(workspaces.administration_departments || []), ...(workspaces.administration_workspaces || [])]; setDepartmentNames(names); setTargets(membershipTargets({ ...user, delegations: owner.delegations }, value.principal, names)); } })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [principal.id]);
  const member = profile?.memberships?.find(item => item.id === selected);
  const targetScope = selected.startsWith("new:") ? targets[Number(selected.slice(4))] : undefined;
  const scope = member?.scope || targetScope;
  const canSetDepartmentRole = canAssignDepartmentRoles(user, principal);
  useEffect(() => {
    if (!profile || selected || !preferredDepartmentID) return;
    const existing = profile.memberships.find(item => item.scope.scope_type === "department" && item.scope.department_id === preferredDepartmentID);
    const index = targets.findIndex(item => item.scope_type === "department" && item.department_id === preferredDepartmentID);
    if (existing) setSelected(existing.id);
    else if (index >= 0) { setSelected(`new:${index}`); setDepartmentRole("member"); }
  }, [profile, targets, preferredDepartmentID, selected]);
  const choose = value => {
    setSelected(value); setPlan(null);
    setDepartmentRole(value.startsWith("new:") ? "member" : "");
    const item = profile.memberships.find(item => item.id === value);
    setStatus(item?.status === "revoked" ? "active" : item?.status || "active");
    setExpiresAt("");
  };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      if (!member && !targetScope) throw new Error("请选择要分配的部门或范围");
      const existing = member || profile.memberships.find(item => JSON.stringify(item.scope) === JSON.stringify(targetScope));
      const change = { subject_type: "user", subject_id: principal.id, expected_revision: profile.principal.revision,
        idempotency_key: crypto.randomUUID(), reason: reason.trim(), memberships: [{ id: existing?.id || `member-${crypto.randomUUID()}`,
          scope: existing?.scope || targetScope, expected_revision: existing?.revision || 0, status,
          ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}) }] };
      if (canSetDepartmentRole && scope.scope_type === "department" && departmentRole && status === "active") {
        const previous = profile.role_bindings.filter(item => item.role_code === "department_admin" && effectiveAccess(item) && item.scope.scope_type === "department" && item.scope.tenant_id === scope.tenant_id && item.scope.department_id === scope.department_id);
        change.revoke_binding_ids = previous.map(item => item.id);
        if (departmentRole === "administrator") change.preset = { preset_code: "department_admin", preset_version: 2, scope, ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}) };
      }
      setPlan(await api.previewIdentityAuthorization(change));
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.commitIdentityAuthorization({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="成员关系管理"><div className="card-heading"><h3>{principal.id} 的成员关系</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    {error && <p role="alert" className="form-error">{error}</p>}
    {!profile ? <p>正在读取成员关系…</p> : profile.policy_mode !== "v2" ? <p>请先完成该账号的权限升级。</p> : protectedTarget ? <p>此账号包含受保护的管理员身份，请由全平台管理员办理变更。</p> : <>
      <form onSubmit={preview}>
        <p>先分配部门，再为用户开通本部门允许使用的 Agent。加入部门不会自动取得 Agent 使用权限。</p>
        <label>所属公司工作空间<input readOnly value={user.workspace_name || "当前公司"}/></label>
        <label>分配部门或调整已有归属<select required value={selected} disabled={busy} onChange={event => choose(event.target.value)}><option value="">请选择部门或已有成员关系</option><optgroup label="新增归属">{targets.map((scope, index) => <option key={index} value={`new:${index}`}>{scope.scope_type === "department" ? "加入部门：" : scope.scope_type === "tenant" ? "公司范围：" : "部门内接入范围："}{scopeLabel(scope)}</option>)}</optgroup><optgroup label="已有归属">{profile.memberships.map(item => <option key={item.id} value={item.id} title={JSON.stringify(item.scope)}>{scopeLabel(item.scope)} · {formatStatus(item.status)}</option>)}</optgroup></select></label>
        <TechnicalDetails values={{ "完整组织范围": member?.scope || targetScope }}/>
        {scope?.scope_type === "department" && canSetDepartmentRole && <label>部门身份<select value={departmentRole} disabled={busy || status !== "active"} onChange={event => { setDepartmentRole(event.target.value); setPlan(null); }}><option value="">保持现有身份</option><option value="member">部门用户</option><option value="administrator">部门管理员</option></select><small>部门用户可获得该部门批准的 Agent；部门管理员还可添加成员，并在公司授权范围内分配 Agent。</small></label>}
        <label>变更为<select value={status} disabled={busy || !member} onChange={event => { setStatus(event.target.value); setPlan(null); }}><option value="active">有效成员</option><option value="revoked">移除成员</option></select></label>
        <label>新到期时间（留空为长期）<input type="datetime-local" value={expiresAt} disabled={busy || status === "revoked"} onChange={event => { setExpiresAt(event.target.value); setPlan(null); }}/></label>
        {member?.expires_at && <p>原到期时间：{formatTime(member.expires_at)}。提交时以本次设置为准。</p>}
        <label>办理原因<textarea required maxLength={1000} value={reason} disabled={busy} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
        <button className="button primary" disabled={busy || !reason.trim() || (!member && !targetScope)} type="submit">预览成员与权限差异</button>
      </form>
      {plan && <div aria-label="成员变更预览"><p>成员状态将改为 {status === "active" ? "有效" : "移除"}；关联的以下权限会同时撤销，已有拒绝规则保留。</p>{scope?.scope_type === "department" && canSetDepartmentRole && <p>部门身份：{departmentRole === "administrator" ? "部门管理员" : departmentRole === "member" ? "部门用户" : "保持现有身份"}</p>}{(plan.expanded_role_bindings || []).map(item => <p key={item.id}>新增岗位：{roleName(item.role_code)}<TechnicalDetails values={{ "角色版本": item.role_version, "完整组织范围": item.scope }}/></p>)}<ul>{(plan.change.revoke_binding_ids || []).map(id => <li key={id}>岗位：{roleName(profile.role_bindings.find(item => item.id === id)?.role_code)}<TechnicalDetails values={{ "岗位授权编号": id }}/></li>)}{(plan.change.revoke_grant_ids || []).map(id => <li key={id}>资源权限：{actionName(profile.resource_grants.find(item => item.id === id)?.action)}<TechnicalDetails values={{ "授权编号": id }}/></li>)}</ul><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>确认提交</button></div>}
    </>}
  </section></Localized>;
}
