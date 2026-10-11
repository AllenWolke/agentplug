import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { formatTime } from "../../format.js";
import { WorkloadCreation } from "./WorkloadCreation.jsx";
import { WorkloadBindingEditor } from "./WorkloadBindingEditor.jsx";
import { ResourceGrantEditor } from "./ResourceGrantEditor.jsx";

function parseCIDRs(value) {
  return String(value || "").split(/[\s,;]+/).map((item) => item.trim()).filter(Boolean);
}

export function MachineCredentialAdmin({ user }) {
  useLanguage();
  const [principals, setPrincipals] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [selectedID, setSelectedID] = useState("");
  const [cidrs, setCIDRs] = useState("");
  const [issued, setIssued] = useState(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [permissionProfile, setPermissionProfile] = useState(null);
  const [permissionError, setPermissionError] = useState("");
  const selected = useMemo(() => credentials.find((item) => item.client_id === selectedID), [credentials, selectedID]);

  const reload = useCallback(async () => {
    const [principalResult, credentialResult] = await Promise.all([
      api.identityPrincipals({ tenant_id: user.tenant_id, principal_type: "service_principal" }),
      api.identityMachineCredentials({ tenant_id: user.tenant_id })
    ]);
    const nextPrincipals = asItems(principalResult);
    const nextCredentials = asItems(credentialResult);
    setPrincipals(nextPrincipals);
    setCredentials(nextCredentials);
    setSelectedID((current) => nextCredentials.some((item) => item.client_id === current) ? current : (nextCredentials[0]?.client_id || ""));
    return { principals: nextPrincipals, credentials: nextCredentials };
  }, [user.tenant_id, user.department_id, user.application_id]);

  useEffect(() => {
    let active = true;
    setIssued(null); setNotice(""); setError("");
    setLoading(true);
    reload().catch((cause) => { if (active) setError(cause.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [reload]);

  useEffect(() => {
    setCIDRs(selected?.network_cidrs?.join("\n") || "");
    setPermissionProfile(null);
    setPermissionError("");
  }, [selected]);

  useEffect(() => {
    if (!selectedID) return;
    let active = true;
    api.identityAccessProfile(selectedID, "service_principal")
      .then((profile) => { if (active) setPermissionProfile(profile); })
      .catch((cause) => { if (active) setPermissionError(cause.message || "无权查看该机器身份的授权"); });
    return () => { active = false; };
  }, [selectedID, selected]);

  const perform = async (action) => {
    setError("");
    setNotice("");
    setBusy(true);
    try { await action(); }
    catch (cause) { setError(cause.message || "机器凭证操作失败"); }
    finally { setBusy(false); }
  };

  const createCredential = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    perform(async () => {
      const values = Object.fromEntries(new FormData(form));
      const networkCIDRs = parseCIDRs(values.network_cidrs);
      if (!networkCIDRs.length) throw new Error("至少填写一个调用来源 CIDR");
      const created = await api.createIdentityMachineCredential({ principal_id: values.principal_id, network_cidrs: networkCIDRs });
      setIssued(created);
      setNotice("Client Secret 仅在本页面内存中展示一次。请立即保存到企业 Secret Manager，切勿提交到代码或工单。");
      form.reset();
      await reload();
      setSelectedID(created.client_id);
    });
  };

  const rotateCredential = () => perform(async () => {
    if (!selected) throw new Error("请选择待轮换的机器凭证");
    const networkCIDRs = parseCIDRs(cidrs);
    if (!networkCIDRs.length) throw new Error("至少填写一个调用来源 CIDR");
    const rotated = await api.rotateIdentityMachineCredential(selected.client_id, { expected_revision: selected.revision, network_cidrs: networkCIDRs });
    setIssued(rotated);
    setNotice("凭证已轮换，旧 Secret 和旧 Token 即时失效；请立即保存新 Secret。");
    await reload();
    setSelectedID(rotated.client_id);
  });

  const disableCredential = () => perform(async () => {
    if (!selected) throw new Error("请选择待禁用的机器凭证");
    await api.disableIdentityMachineCredential(selected.client_id, selected.revision);
    setIssued(null);
    setNotice("凭证已禁用，后续 Token 签发和已签发 Token 调用都会被拒绝。");
    await reload();
  });

  if (loading) return <Localized><div className="state-panel">正在读取机器凭证…</div></Localized>;
  if (error && !credentials.length && !principals.length) return <Localized><section className="state-panel error"><b>机器凭证读取失败</b><p>{error}</p><button className="button secondary" onClick={() => { setError(""); setLoading(true); reload().catch((cause) => setError(cause.message)).finally(() => setLoading(false)); }}>重新加载</button></section></Localized>;

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">机器凭证</p><h2>机器身份凭证</h2><p>由平台管理员签发和轮换 Client Secret；机器调用方通过 client_credentials 换取短时 Token。每个请求仍按当前 Identity Grant、安装实例、来源网络和凭证 revision 实时校验。</p></div></div>
    {notice && <div className="success-banner" role="status">{notice}</div>}
    {error && <div className="form-error page-error" role="alert">{error}</div>}
    <section className="two-column">
      {user.policy_mode === "v2" ? <WorkloadCreation key={[user.tenant_id, user.department_id, user.application_id].join("/")} user={user} onCreated={async created => {
        setIssued(created);
        setNotice("机器主体已创建，尚无业务权限或 Agent 绑定。请立即安全保存一次性 Secret，并继续办理授权和绑定。");
        const next = await reload();
        if (next.credentials.some(item => item.client_id === created.client_id)) setSelectedID(created.client_id);
      }}/> : <article className="card"><h3>签发凭证</h3><form id="create-machine-credential-form" className="form" onSubmit={createCredential}>
        <label><span>已登记机器主体</span><select name="principal_id" required defaultValue=""><option value="">选择无管理角色的 Service Principal</option>{principals.filter((item) => item.is_active).map((item) => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label>
        <label><span>调用来源 CIDR</span><textarea name="network_cidrs" rows="4" placeholder="例如：10.20.0.0/16，每行一个；按调用方实际出口配置" required/></label>
        <button className="button primary" disabled={busy || !principals.some((item) => item.is_active)}>生成一次性 Client Secret</button>
      </form><p className="form-hint">仅保存 Secret 哈希；Secret 不返回列表、不进入 localStorage/sessionStorage。请勿使用 0.0.0.0/0 或 ::/0 作为生产网络范围。</p></article>}
      <article className="card"><h3>轮换 / 禁用凭证</h3>{credentials.length ? <>
        <label><span>凭证</span><select value={selectedID} onChange={(event) => setSelectedID(event.target.value)}>{credentials.map((item) => <option key={item.client_id} value={item.client_id}>{item.client_id} · {item.status} · r{item.revision}</option>)}</select></label>
        <label><span>来源 CIDR</span><textarea id="machine-credential-cidrs" rows="4" value={cidrs} onChange={(event) => setCIDRs(event.target.value)}/></label>
        <div className="inline-form"><button className="button secondary" type="button" disabled={busy || selected?.status !== "active"} onClick={rotateCredential}>轮换并撤销旧 Token</button><button className="button secondary danger" type="button" disabled={busy || selected?.status !== "active"} onClick={disableCredential}>禁用凭证</button></div>
      </> : <div className="empty"><b>暂无凭证</b><p>登记机器主体并配置最小权限 Grant 后，可在此签发 Client Secret。</p></div>}</article>
    </section>
    {selectedID && <section className="card"><h3>机器身份的执行授权</h3>
      {user.policy_mode === "v2" && <WorkloadBindingEditor key={selectedID + user.application_id} user={user} principalID={selectedID} onSaved={async () => { await reload(); setPermissionProfile(await api.identityAccessProfile(selectedID, "service_principal")); }}/>}
      {user.policy_mode === "v2" && permissionProfile && user.capabilities?.includes("authorization.change") && <ResourceGrantEditor key={selectedID + user.application_id} user={user} profile={permissionProfile} onRefresh={async () => setPermissionProfile(await api.identityAccessProfile(selectedID, "service_principal"))} onSaved={async () => { setPermissionProfile(await api.identityAccessProfile(selectedID, "service_principal")); setNotice("机器资源权限已更新。"); }}/>}
      <p>凭证有效不等于可执行。机器只能使用下列明确授权的资源，实际调用还需同时满足业务用户的权限。</p>
      {permissionError && <p className="form-error" role="alert">{permissionError}</p>}
      {permissionProfile && <><p>主体：{permissionProfile.principal.id} · 权限修订 {permissionProfile.principal.revision}</p>
        {(permissionProfile.resource_grants || []).length ? <div className="simple-table">{permissionProfile.resource_grants.map((grant) => <div key={grant.id}>
          <span><b>{grant.resource_id} · {grant.action}</b><small>{grant.agent_instance_id} · {grant.data_scope?.type} · 来源 {grant.source_id}</small></span>
          <span>{grant.effect} · {grant.status} · {grant.expires_at ? formatTime(grant.expires_at) : "长期"}</span>
        </div>)}</div> : <p>当前可查看范围内没有资源授权。</p>}</>}
    </section>}
    {issued && <section className="card one-time-secret" role="status"><h3>一次性 Secret — 仅此刻可见</h3><p>请立即将 Secret 安全写入调用方 Secret Manager。刷新或离开此页后平台不会再次提供明文。</p><p>Client ID：<code>{issued.client_id}</code></p><p>Client Secret：<code data-testid="one-time-client-secret">{issued.client_secret}</code></p><button className="button secondary" type="button" onClick={() => setIssued(null)}>已安全保存，清除页面 Secret</button></section>}
    <section className="card"><div className="card-heading"><h3>凭证台账</h3><span>{credentials.length} 条 · 仅展示元数据</span></div>{credentials.length ? <div className="simple-table">{credentials.map((item) => <div key={item.client_id}><span><b>{item.client_id}</b><small>{item.network_cidrs.join(", ")} · revision {item.revision} · 更新于 {formatTime(item.updated_at)}</small></span><span className={`badge ${item.status === "active" ? "success" : "danger"}`}>{item.status}</span></div>)}</div> : <div className="empty"><b>暂无机器凭证</b><p>创建后的凭证元数据会显示在这里，Secret 不会出现在台账中。</p></div>}</section>
  </></Localized>;
}
