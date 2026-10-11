import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { installationName } from "../../presentation.js";
import { formatStatus } from "../../format.js";
import { TechnicalDetails } from "../../components/DisplayNames.jsx";

export function WorkloadBindingEditor({ user, principalID, onSaved }) {
  useLanguage();
  const [installations, setInstallations] = useState([]), [bindings, setBindings] = useState([]);
  const [installationID, setInstallationID] = useState(""), [reason, setReason] = useState("");
  const [command, setCommand] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("");
  const scope = { tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id };
  const load = () => Promise.all([api.identityInstallationTargets(scope, "workload"), api.identityWorkloadBindings(scope)]);
  const apply = ([catalog, directory]) => { setInstallations(asItems(catalog).filter(item => ["active", "provisioning"].includes(item.status))); setBindings(asItems(directory)); };
  useEffect(() => { let active = true; load().then(value => { if (active) apply(value); }).catch(cause => { if (active) setError(cause.message); }); return () => { active = false; }; }, [user.tenant_id, user.department_id, user.application_id]);
  const installation = installations.find(item => item.id === installationID), current = bindings.find(item => item.installation_id === installationID);
  const preview = event => { event.preventDefault(); setCommand({ binding: { ...scope, installation_id: installation.id, agent_id: installation.agent_id, agent_version_id: installation.version_id, principal_id: principalID }, expected_revision: current?.revision || 0, revoke: event.nativeEvent.submitter?.value === "revoke", reason: reason.trim(), idempotency_key: crypto.randomUUID() }); };
  const commit = async () => { setBusy(true); setError(""); setNotice("");
    try { const receipt = await api.changeIdentityWorkloadBinding(command); setCommand(null); apply(await load()); await onSaved(); setNotice(`绑定已更新：${formatStatus(receipt.binding.status)} · 版本 ${receipt.binding.revision}`); }
    catch (cause) { setError(cause.message); if (cause.status === 409) { setCommand(null); await load().then(apply).catch(() => {}); } } finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="机器安装绑定"><h3>机器执行身份与 Agent 安装绑定</h3><p>主体：{principalID}。绑定不授予资源权限。</p>{error && <p role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}
    <form onSubmit={preview}><label>当前应用智能体<select required value={installationID} disabled={busy} onChange={event => { setInstallationID(event.target.value); setCommand(null); }}><option value="">请选择</option>{installations.map(item => <option key={item.id} value={item.id} title={item.id}>{installationName(item)}</option>)}</select></label>
      {installation && <div><p>{installationName(installation)} · 当前绑定：{current ? `${current.principal_id} · ${formatStatus(current.status)} · 版本 ${current.revision}` : "尚未绑定"}</p><TechnicalDetails values={{ "智能体版本编号": installation.version_id, "机器绑定编号": current?.id }}/></div>}
      {current?.status === "active" && current.principal_id !== principalID && <p>安装已绑定其他机器，须先明确撤销原绑定。</p>}
      <label>办理原因<textarea required maxLength={1000} value={reason} disabled={busy} onChange={event => { setReason(event.target.value); setCommand(null); }}/></label>
      <button type="submit" className="button primary" value="bind" disabled={busy || !installation || !reason.trim() || current?.status === "active" && current.principal_id !== principalID}>核对绑定变更</button>
      <button type="submit" className="button secondary" value="revoke" disabled={busy || current?.status !== "active" || current.principal_id !== principalID || !reason.trim()}>核对撤销绑定</button></form>
    {command && <div aria-label="机器绑定变更核对"><p>{command.revoke ? "撤销" : "建立"} {installationName(installation)} 与机器 {principalID} 的绑定。提交时核对当前绑定版本 {command.expected_revision}。</p><p>{command.reason}</p><TechnicalDetails values={{ "智能体安装编号": command.binding.installation_id, "智能体版本编号": command.binding.agent_version_id, "目标机器账号": principalID }}/><button className="button primary" disabled={busy} onClick={commit}>确认提交绑定变更</button></div>}
  </section></Localized>;
}
