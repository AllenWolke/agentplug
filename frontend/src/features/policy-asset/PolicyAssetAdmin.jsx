import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { policyAssetActions } from "./policy-asset-access.js";

const TYPES = ["model", "prompt", "tool", "memory", "knowledge", "runtime"];
const itemsOf = (value) => Array.isArray(value?.items) ? value.items : [];
const scopeOf = (installation) => ({
  tenant_id: installation.tenant_id,
  department_id: installation.department_id,
  application_id: installation.application_id,
  agent_id: installation.agent_id,
  agent_version_id: installation.version_id,
});
const defaults = {
  model: { provider: "local", model: "approved-model", max_tokens: 2048, temperature: 0, allow_external: false, budget_cents: 0, input_micros_per_1k_tokens: 0, output_micros_per_1k_tokens: 0 },
  prompt: { template: "你是受控业务 Agent。", template_hash: "" },
  tool: { allowed_tools: ["approved-tool"], require_confirmation: [] },
  memory: { working_ttl_seconds: 3600, session_ttl_seconds: 86400, task_ttl_seconds: 604800, max_entries: 100, long_term_enabled: false, semantic_enabled: false },
  knowledge: { allowed_scopes: ["local"], require_references: true, allow_partial_degraded: false, allow_replay: true },
  runtime: { max_attempts: 3, task_timeout_seconds: 120, lease_seconds: 30, cancel_grace_seconds: 5 },
};

async function contentFromForm(type, raw) {
  let content;
  try { content = JSON.parse(raw); } catch { throw new Error("策略内容必须是有效 JSON"); }
  if (!content || typeof content !== "object" || Array.isArray(content)) throw new Error("策略内容必须是 JSON 对象");
  if (type === "prompt" && content.template && !content.template_hash) {
    const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content.template));
    content.template_hash = Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return content;
}

// Management edits versioned assets only. Execution reads the published SQL
// snapshot through its own Resolver; the browser never chooses a runtime policy.
// 管理页仅修改版本化资产；执行端从 SQL Resolver 读取已发布快照，
// 浏览器不能为单次运行指定策略。
export default function PolicyAssetAdmin({ user, onProjection }) {
  useLanguage();
	const access = policyAssetActions(user);
	const allowedTypes = access.types;
	const authorityKey = [user.username, user.policy_mode, user.tenant_id, user.department_id, user.application_id, allowedTypes.join(","), access.snapshot].join("|");
	const generation = useRef(0);
  const [installations, setInstallations] = useState([]);
  const [installationID, setInstallationID] = useState("");
  const [assets, setAssets] = useState([]);
  const [references, setReferences] = useState([]);
  const [snapshot, setSnapshot] = useState(null);
  const [type, setType] = useState(allowedTypes[0] || "model");
  const [content, setContent] = useState(JSON.stringify(defaults[allowedTypes[0] || "model"], null, 2));
  const [selected, setSelected] = useState({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const installation = installations.find((item) => item.id === installationID);
  const scope = installation ? scopeOf(installation) : null;

  useEffect(() => {
    let active = true, sequence = 0;
    const refresh = async () => {
      const ticket = ++sequence;
      try {
        const projection = await api.identityPermissions();
        if (!active || ticket !== sequence) return;
        const projectedScope = projection.scope;
        if (user.policy_mode === "v2" && (projection.policy_mode !== "v2" || projectedScope?.scope_type !== "application" || projectedScope.tenant_id !== user.tenant_id || projectedScope.department_id !== user.department_id || projectedScope.application_id !== user.application_id)) throw new Error("策略权限响应范围不匹配");
        onProjection?.(projection, user);
      } catch (reason) {
        if (active && ticket === sequence) { generation.current++; setAssets([]); setReferences([]); setSnapshot(null); setSelected({}); setBusy(false); setError(reason.message || "无法核验当前策略权限"); }
      }
    };
    refresh();
    const timer = setInterval(refresh, 15000);
    window.addEventListener("focus", refresh);
    return () => { active = false; sequence++; generation.current++; clearInterval(timer); window.removeEventListener("focus", refresh); };
  }, [user.username, user.policy_mode, user.tenant_id, user.department_id, user.application_id, onProjection]);

  useEffect(() => {
    if (allowedTypes.includes(type)) return;
    const next = allowedTypes[0] || "model";
    setType(next); setContent(JSON.stringify(defaults[next], null, 2));
  }, [authorityKey, type]);

  useEffect(() => {
    let active = true;
    setInstallations([]); setInstallationID(""); setAssets([]); setSnapshot(null); setSelected({});
    if (!allowedTypes.includes(type)) return () => { active = false; };
    api.catalogInstallations({ tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id, view: "policy-assets", asset_type: type })
      .then((result) => { if (active) { const rows = itemsOf(result); setInstallations(rows); setInstallationID(rows[0]?.id || ""); } })
      .catch((reason) => { if (active) setError(reason.message || "无法加载当前应用安装目录"); });
    return () => { active = false; };
  }, [authorityKey, type]);

  const reload = async (target = scope) => {
    if (!target) return;
    const ticket = generation.current;
    const [assetResult, snapshotResult, referencesResult] = await Promise.allSettled([api.policyAssets(target, type), access.snapshot ? api.currentPolicySnapshot(target) : Promise.resolve(null), access.snapshot ? api.policyAssetReferences(target) : Promise.resolve({ items: [] })]);
    if (ticket !== generation.current) return;
    if (assetResult.status === "rejected") throw assetResult.reason;
    setAssets(itemsOf(assetResult.value));
    if (referencesResult.status === "rejected") throw referencesResult.reason;
    setReferences(itemsOf(referencesResult.value));
    if (snapshotResult.status === "fulfilled") setSnapshot(snapshotResult.value ? { ...snapshotResult.value, revision: snapshotResult.value.revision ?? snapshotResult.value.Revision } : null);
    else if (snapshotResult.reason?.status === 404) setSnapshot(null);
    else throw snapshotResult.reason;
  };
  useEffect(() => {
    const ticket = ++generation.current;
    setAssets([]); setReferences([]); setSnapshot(null); setSelected({}); setNotice(""); setBusy(false);
    if (!scope) { setAssets([]); setSnapshot(null); return; }
    let active = true;
    Promise.allSettled([api.policyAssets(scope, type), access.snapshot ? api.currentPolicySnapshot(scope) : Promise.resolve(null), access.snapshot ? api.policyAssetReferences(scope) : Promise.resolve({ items: [] })]).then(([assetResult, snapshotResult, referencesResult]) => {
      if (!active || ticket !== generation.current) return;
      if (assetResult.status === "rejected") { setError(assetResult.reason.message || "策略查询失败"); return; }
      setAssets(itemsOf(assetResult.value));
      if (referencesResult.status === "fulfilled") setReferences(itemsOf(referencesResult.value));
      else { setError(referencesResult.reason.message || "发布引用查询失败"); return; }
      if (snapshotResult.status === "fulfilled") setSnapshot(snapshotResult.value ? { ...snapshotResult.value, revision: snapshotResult.value.revision ?? snapshotResult.value.Revision } : null);
      else if (snapshotResult.reason?.status === 404) setSnapshot(null);
      else setError(snapshotResult.reason.message || "快照查询失败");
    });
    return () => { active = false; if (generation.current === ticket) generation.current++; };
  }, [installationID, type, authorityKey]);

  const run = async (action, message) => {
    const ticket = generation.current;
    setBusy(true); setError(""); setNotice("");
    try { await action(); if (ticket !== generation.current) return; await reload(); if (ticket === generation.current) setNotice(message); }
    catch (reason) { if (ticket === generation.current) { setAssets([]); setReferences([]); setSnapshot(null); setError(reason.message || "操作失败；请检查 revision 和当前权限"); } }
    finally { if (ticket === generation.current) setBusy(false); }
  };
  const create = (event) => {
    event.preventDefault();
    const id = String(new FormData(event.currentTarget).get("asset_id") || "").trim();
    if (!scope) return;
    run(async () => api.createPolicyAsset({ id, type, scope, content: await contentFromForm(type, content) }), "策略资产已创建为 draft；发布后才能进入运行快照。");
  };
  const published = Object.fromEntries(TYPES.map((assetType) => [assetType, references.filter((item) => item.type === assetType && item.status === "published")]));
  const publishSnapshot = () => {
    if (!scope || !access.snapshot) return;
    run(async () => {
      const refs = {};
      for (const assetType of TYPES) {
        const row = published[assetType].find((item) => item.id === selected[assetType]) || (published[assetType].length === 1 ? published[assetType][0] : null);
        if (!row) throw new Error(`请选择已发布的 ${assetType} 资产`);
        refs[assetType] = { id: row.id, revision: row.revision };
      }
      await api.publishPolicySnapshot({ scope, expected_revision: snapshot?.revision || 0, assets: refs });
    }, "六类策略快照已原子发布；后续运行按新 revision 解析。");
  };

  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">运行配置</p><h2>六类策略资产与运行快照</h2><p>为精确 Agent Version 管理 Model、Prompt、Tool、Memory、Knowledge、Runtime；发布快照使用 revision CAS。</p></div><button className="button secondary" disabled={!scope || busy} onClick={() => run(async () => {}, "已刷新策略资产")}>刷新</button></div>
    {error && <div className="form-error page-error">{error}</div>}{notice && <div className="success-banner">{notice}</div>}
    <section className="card"><label><span>当前应用 Agent 安装</span><select value={installationID} onChange={(event) => { setInstallationID(event.target.value); setSelected({}); setError(""); }}><option value="">选择安装实例</option>{installations.map((item) => <option key={item.id} value={item.id}>{item.display_name || item.agent_id} · {item.id} · {item.version_id}</option>)}</select></label>{!scope && <p className="form-hint">当前应用没有可管理的 Agent 安装实例。</p>}{scope && <p className="form-hint">作用域：{scope.tenant_id} / {scope.department_id} / {scope.application_id} / {scope.agent_id} / {scope.agent_version_id}</p>}</section>
    {scope && <><section className="two-column"><article className="card"><h3>新增策略资产</h3><form className="form" onSubmit={create}><label><span>资产类型</span><select value={type} onChange={(event) => { const next = event.target.value; setType(next); setContent(JSON.stringify(defaults[next], null, 2)); }}>{allowedTypes.map((item) => <option key={item} value={item}>{item}</option>)}</select></label><label><span>稳定资产 ID</span><input name="asset_id" pattern="[A-Za-z0-9._:-]{1,128}" required placeholder="例如 policy-model-v1"/></label><label><span>策略 JSON</span><textarea value={content} onChange={(event) => setContent(event.target.value)} rows={10} spellCheck="false"/></label><button className="button primary" disabled={busy}>创建 draft</button></form></article><article className="card"><h3>已登记资产</h3>{assets.length ? <div className="record-list">{assets.map((asset) => <div key={`${asset.type}:${asset.id}`}><span className="record-icon">{asset.type[0].toUpperCase()}</span><span><b>{asset.type} · {asset.id}</b><small>{asset.status} · revision {asset.revision} · {asset.content_hash?.slice(0, 16)}</small></span>{asset.status === "draft" && allowedTypes.includes(asset.type) && <button className="button secondary" disabled={busy} onClick={() => run(() => api.publishPolicyAsset(asset.type, asset.id, { scope, expected_revision: asset.revision }), `${asset.id} 已发布`)}>发布</button>}</div>)}</div> : <p className="form-hint">暂无资产。先创建并逐项发布六类策略。</p>}</article></section>
      {access.snapshot && <section className="card"><div className="card-heading"><div><h3>原子发布运行快照</h3><p className="form-hint">必须为六类资产各选一个已发布版本；冲突时刷新 revision 再提交，不会覆盖其他管理员的发布。</p></div><span>当前 revision：{snapshot?.revision || 0}</span></div><div className="policy-editor-grid">{TYPES.map((assetType) => <label key={assetType}><span>{assetType}</span><select value={selected[assetType] || ""} onChange={(event) => setSelected({ ...selected, [assetType]: event.target.value })}><option value="">{published[assetType].length === 1 ? `自动选择 ${published[assetType][0].id}` : "选择已发布资产"}</option>{published[assetType].map((item) => <option key={item.id} value={item.id}>{item.id} · r{item.revision}</option>)}</select></label>)}</div><button className="button primary" disabled={busy || TYPES.some((assetType) => !published[assetType].length)} onClick={publishSnapshot}>发布六策略快照</button></section>}</>}
  </></Localized>;
}
