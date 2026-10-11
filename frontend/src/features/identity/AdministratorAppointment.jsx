import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { FreshAuthentication } from "./FreshAuthentication.jsx";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { roleName } from "../../presentation.js";
import { isProtectedAdministratorBinding } from "./administration-state.js";

export function AdministratorAppointment({ principal, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [profile, setProfile] = useState(null);
  const [role, setRole] = useState("tenant_admin");
  const [scopeIndex, setScopeIndex] = useState("");
  const [expires, setExpires] = useState("");
  const [revocations, setRevocations] = useState([]);
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api.identityAccessProfile(principal.id).then(value => { if (active) setProfile(value); })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [principal.id]);
  const members = (profile?.memberships || []).filter(item => item.status === "active" && ["tenant", "department", "application"].includes(item.scope.scope_type));
  const invalidate = () => { setPlan(null); };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); invalidate();
    try {
      const scope = role === "tenant_admin" ? { scope_type: "tenant", tenant_id: profile.principal.tenant_id } : role === "super_admin" ? { scope_type: "global" } : role ? members[Number(scopeIndex)]?.scope : { scope_type: "global" };
      if (role === "permission_admin" && scopeIndex === "") throw new Error("请选择权限管理员的组织范围");
      const command = { subject_id: principal.id, expected_revision: profile.principal.revision, idempotency_key: crypto.randomUUID(), reason: reason.trim(), role_code: role, scope, revoke_binding_ids: revocations,
        ...(role === "tenant_admin" ? { role_version: 2 } : {}),
        ...(expires && role ? { expires_at: new Date(expires).toISOString() } : {}) };
      setPlan(await api.previewAdministratorAppointment(command));
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async proof => {
    setError("");
    try {
      const receipt = await api.appointIdentityAdministrator({ ...plan.change, step_up_token: proof.step_up_token });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); throw cause; }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="管理员任命">
    <div className="card-heading"><h3>管理员任命 · {principal.id}</h3><button className="button secondary" onClick={onClose} disabled={busy}>关闭</button></div>
    {error && <div className="form-error" role="alert">{error}</div>}
    {!profile ? <p>正在读取身份与认证状态…</p> : profile.policy_mode !== "v2" ? <p>此账号尚未完成权限升级。</p> : <>
      <form onSubmit={preview}>
        <label>任命身份<select value={role} disabled={busy} onChange={event => { setRole(event.target.value); setScopeIndex(""); invalidate(); }}><option value="tenant_admin">公司管理员</option><option value="permission_admin">权限管理员</option><option value="super_admin">超级管理员</option><option value="">仅撤销管理员身份</option></select></label>
        {role === "tenant_admin" && <div className="form-hint"><p>公司范围：{scopeLabel({ scope_type: "tenant", tenant_id: profile.principal.tenant_id })}</p><p>可创建部门、管理部门成员、设置部门管理员，并在本公司内办理 Agent 授权和管理委托。不会获得全平台管理或业务数据访问权限。</p><p>原管理员身份需单独勾选撤销；仅新增公司管理员不会自动收回原有权限。</p></div>}
        {role === "permission_admin" && <label>授权办理范围<select value={scopeIndex} required disabled={busy} onChange={event => { setScopeIndex(event.target.value); invalidate(); }}><option value="">请选择</option>{members.map((item, index) => <option key={item.id} value={index} title={JSON.stringify(item.scope)}>{scopeLabel(item.scope)}</option>)}</select></label>}
        {role && <label>到期时间（留空为长期）<input type="datetime-local" value={expires} disabled={busy} onChange={event => { setExpires(event.target.value); invalidate(); }}/></label>}
        <fieldset><legend>同时撤销的原管理员身份</legend>{(profile.role_bindings || []).filter(item => item.status === "active" && isProtectedAdministratorBinding(item)).map(item => <div className="permission-record" key={item.id}><label><input type="checkbox" checked={revocations.includes(item.id)} disabled={busy} onChange={event => { setRevocations(current => event.target.checked ? [...current, item.id] : current.filter(id => id !== item.id)); invalidate(); }}/>{roleName(item)} · {scopeLabel(item.scope)}</label><TechnicalDetails values={{ "绑定编号": item.id, "组织范围": JSON.stringify(item.scope) }}/></div>)}</fieldset>
        <label>任命或撤销原因<textarea value={reason} required maxLength={2000} disabled={busy} onChange={event => { setReason(event.target.value); invalidate(); }}/></label>
        <button className="button primary" disabled={busy || !reason.trim() || (!role && !revocations.length)}>预览管理员变更</button>
      </form>
      {plan && <><p>任命：{role ? roleName({ role_code: role, role_version: role === "tenant_admin" ? 2 : 1 }) : "无新增"}；撤销 {revocations.length} 项。{role === "permission_admin" && "任命后还需配置明确委托，才能办理授权。"}</p><FreshAuthentication key={plan.request_digest} action={plan.step_up_action} requestDigest={plan.request_digest} onProof={commit} onBusy={setBusy}/></>}
    </>}
  </section></Localized>;
}
