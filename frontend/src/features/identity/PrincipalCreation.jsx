import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { useScopeName } from "../../components/DisplayNames.jsx";
import { roleName } from "../../presentation.js";

export function PrincipalCreation({ user, onSaved, onClose }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [presetCode, setPresetCode] = useState("");
  const [presets, setPresets] = useState([]);
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [command, setCommand] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    api.identityPresets().then(value => { if (active) setPresets(asItems(value).filter(item => item.subject_type === "user" && !item.appointment_only && item.scope_types?.includes("application"))); }).catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, []);
  const change = setter => event => { setter(event.target.value); setPlan(null); setCommand(null); };
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      const scope = { scope_type: "application", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id };
      const validity = expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {};
      const preset = presets.find(item => item.preset_code === presetCode);
      const next = { username, display_name: displayName.trim(), scope, ...validity, reason: reason.trim(), idempotency_key: crypto.randomUUID(),
        ...(preset ? { preset: { preset_code: preset.preset_code, preset_version: preset.preset_version, scope, resource_ids: [], ...validity } } : {}) };
      setPlan(await api.previewPermissionPrincipal(next)); setCommand(next);
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.createPermissionPrincipal({ ...command, password, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      setPassword(""); await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="新建用户"><div className="card-heading"><h3>在当前工作空间新建用户</h3><button className="button secondary" disabled={busy} onClick={() => { setPassword(""); onClose(); }}>关闭</button></div>
    {error && <p role="alert" className="form-error">{error}</p>}
    <form onSubmit={preview}>
      <p>工作空间：{scopeLabel({ scope_type: "application", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id })}</p>
      <label>账号名<input required minLength={3} maxLength={64} pattern="[a-zA-Z][a-zA-Z0-9._\-]{2,63}" autoComplete="off" value={username} disabled={busy} onChange={change(setUsername)}/></label>
      <label>显示名<input required minLength={2} maxLength={128} value={displayName} disabled={busy} onChange={change(setDisplayName)}/></label>
      <label>初始密码<input type="password" required minLength={10} maxLength={128} autoComplete="new-password" value={password} disabled={busy} onChange={change(setPassword)}/></label>
      <label>岗位身份<select value={presetCode} disabled={busy} onChange={change(setPresetCode)}><option value="">仅创建身份与成员关系</option>{presets.map(item => <option key={`${item.preset_code}:${item.preset_version}`} value={item.preset_code}>{item.name}</option>)}</select></label>
      <label>成员和岗位到期时间（留空为长期）<input type="datetime-local" value={expiresAt} disabled={busy} onChange={change(setExpiresAt)}/></label>
      <label>创建原因<textarea required maxLength={1000} value={reason} disabled={busy} onChange={change(setReason)}/></label>
      <button className="button primary" disabled={busy} type="submit">预览创建结果</button>
    </form>
    {plan && <div aria-label="用户创建预览"><p>创建 {command.username}，加入 {scopeLabel(command.scope)}。</p><ul>{asItems(plan.expanded_role_bindings).map(item => <li key={item.id}>岗位：{roleName(item)}（版本 {item.role_version}）</li>)}</ul><p>Agent 使用权限可在创建后通过「身份与权限」办理。</p><button className="button primary" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>确认创建用户</button></div>}
  </section></Localized>;
}
