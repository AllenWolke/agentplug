import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { administrationKind } from "./administration-state.js";
import { membershipTargets } from "./organization-access.js";
import { departmentBatchCommand, loadBatchProfiles } from "./permission-batch.js";
import { PermissionBatchProgress } from "./PermissionBatchProgress.jsx";
import { BatchAgentUseForm, AgentUseResources } from "./BatchAgentUseForm.jsx";

export function BatchDepartmentAssignment({ user, principals, operation = "department", onLockedChange, onSaved, onClear }) {
  useLanguage();
  const [workspaces, setWorkspaces] = useState([]), [targets, setTargets] = useState([]);
  const [owner, setOwner] = useState(null);
  const [loadingScopes, setLoadingScopes] = useState(true), [scopeGeneration, setScopeGeneration] = useState(0);
  const [departmentIndex, setDepartmentIndex] = useState(""), [role, setRole] = useState("keep");
  const [expiresAt, setExpiresAt] = useState(""), [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null), [busy, setBusy] = useState(false), [locked, setLocked] = useState(false), [error, setError] = useState("");
  const scopeLabel = useScopeName(workspaces);
  const canSetRoles = ["platform", "company"].includes(administrationKind(user));
  const canDepartments = user.capabilities?.includes("membership.manage");
  const mode = canDepartments ? operation : "agent";
  useEffect(() => {
    let active = true;
    setLoadingScopes(true); setOwner(null); setError("");
    Promise.all([api.identityWorkspaces(), api.identityAccessProfile(user.username)]).then(([value, owner]) => {
      if (!active) return;
      const names = [...(value.administration_departments || []), ...(value.administration_workspaces || [])];
      setWorkspaces(names);
      setOwner(owner);
      setTargets(membershipTargets({ ...user, delegations: owner.delegations || [] }, { tenant_id: user.tenant_id }, names).filter(scope => scope.scope_type === "department" && scope.department_id));
    }).catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setLoadingScopes(false); });
    return () => { active = false; };
  }, [user.tenant_id, user.username, scopeGeneration]);
  useEffect(() => { setPlan(null); }, [principals]);
  useEffect(() => { setPlan(null); }, [mode]);
  useEffect(() => { onLockedChange?.(locked || busy); }, [locked, busy, onLockedChange]);
  const preview = async event => {
    event.preventDefault(); if (busy || locked) return;
    setBusy(true); setError(""); setPlan(null);
    try {
      const profiles = await loadBatchProfiles(api, principals.map(item => item.id));
      const command = departmentBatchCommand({ user, principals, profiles, department: targets[Number(departmentIndex)], role,
        expiresAt, reason, key: crypto.randomUUID(), newID: () => `member-${crypto.randomUUID()}` });
      setPlan(await api.previewPermissionBatch(command));
    } catch (cause) { setError(cause.message || "无法生成批量变更预览。"); }
    finally { setBusy(false); }
  };
  const reset = () => { setPlan(null); setReason(""); setError(""); onClear?.(); };
  return <Localized><>
    {principals.length > 0 && !locked && mode === "agent" && (loadingScopes ? <p role="status">正在读取管理范围…</p> : owner ? <BatchAgentUseForm user={user} owner={owner} workspaces={workspaces} principals={principals} onPreview={setPlan} onBusyChange={setBusy}/> : <section className="card"><p className="form-error" role="alert">{error || "无法读取管理范围，请重试。"}</p><button className="button secondary" onClick={() => setScopeGeneration(value => value + 1)}>重新读取管理范围</button></section>)}
    {principals.length > 0 && !locked && mode === "department" && <section id="batch-department-assignment" className="card batch-department-assignment" aria-label="批量分配部门与身份">
      <div className="card-heading"><h3>批量分配部门与身份</h3><span>已选 {principals.length} 位用户</span></div>
      <p>一次选择共同部门和身份，先核对每人的结果。其他部门、Agent 权限和拒绝规则会保留。</p>
      <form className="form" onSubmit={preview}><fieldset disabled={busy}>
        <label>目标部门<select required value={departmentIndex} onChange={event => { setDepartmentIndex(event.target.value); setPlan(null); }}><option value="">请选择部门</option>{targets.map((scope, index) => <option key={JSON.stringify(scope)} value={index}>{scopeLabel(scope)}</option>)}</select></label>
        {canSetRoles ? <label>部门身份<select value={role} onChange={event => { setRole(event.target.value); setPlan(null); }}><option value="keep">保留已有身份，新成员设为部门用户</option><option value="member">全部设为部门用户</option><option value="administrator">全部设为部门管理员</option></select></label> : <p className="form-hint">新成员加入后为部门用户。部门管理员身份由公司管理员设置。</p>}
        {role === "member" && <p className="notice">本次会撤销所选用户在目标部门的管理员身份，其业务权限仍需在预览中核对。</p>}
        {role === "administrator" && <p className="notice">所选用户将能添加本部门成员，并分配公司批准的 Agent。管理身份不会自动开通业务使用权限。</p>}
        <label>统一到期时间（留空保留已有期限）<input type="datetime-local" value={expiresAt} onChange={event => { setExpiresAt(event.target.value); setPlan(null); }}/></label>
        <p className="form-hint">已在部门的成员保留原开始时间；留空也保留原到期时间。新成员须符合你的可管理期限。</p>
        <label>共同办理原因<textarea required maxLength={1000} value={reason} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
        <button className="button primary" disabled={busy || !reason.trim() || departmentIndex === ""} type="submit">预览每人的变更</button>
      </fieldset></form>
      {error && <p className="form-error" role="alert">{error}</p>}
    </section>}
    <PermissionBatchProgress user={user} kind="authorization" plan={plan} onLockedChange={setLocked} onReset={reset} onChanged={onSaved} describeItem={item => <>
      <p className="form-hint">{item.command.authorization?.agent_use ? "开通 Agent 个人会话与已发布依赖，保留其他权限和拒绝规则" : item.command.authorization?.preset?.preset_code === "department_admin" ? "加入部门并设为部门管理员" : item.command.authorization?.revoke_binding_ids?.length ? "加入部门并设为部门用户，收回原部门管理员身份" : "加入部门，保留已有身份"}</p>
      {item.command.authorization?.agent_use && <><p className="form-hint">{scopeLabel(item.command.authorization.agent_use.scope)}</p><AgentUseResources counts={item.impact?.resource_counts}/></>}
      {!!item.command.authorization?.revoke_grant_ids?.length && <p className="form-hint">关联资源权限将撤销 {item.command.authorization.revoke_grant_ids.length} 项</p>}
      <TechnicalDetails values={{ "成员变更": item.command.authorization?.memberships, "撤销岗位编号": item.command.authorization?.revoke_binding_ids }}/>
    </>}/>
  </></Localized>;
}
