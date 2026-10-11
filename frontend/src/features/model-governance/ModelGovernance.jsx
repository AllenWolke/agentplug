import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { BillingReconciliation } from "./BillingReconciliation.jsx";
import { formatStatus, formatTime, shortId, statusTone } from "../../format.js";

const itemsOf = (value) => {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  if (Array.isArray(value?.data?.items)) return value.data.items;
  if (Array.isArray(value?.data)) return value.data;
  return [];
};
const parseObject = (value, name) => {
  try {
    const parsed = JSON.parse(String(value || "{}"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch { throw new Error(`${name} 必须是 JSON 对象`); }
};

// This page is the control-plane view. Decisions, credentials and accounting
// remain server-side; the browser only submits SecretRef and immutable IDs.
// 页面只负责控制面展示，决策、密钥和计费均在服务端完成。
export function ModelGovernance({ lastDaysRange }) {
  useLanguage();
  const [data, setData] = useState({ usage: null, usageRuns: [], providers: [], models: [], versions: [], prices: [], deployments: [], policies: [] });
  const [usageRange, setUsageRange] = useState({});
  const [selectedUsageRunID, setSelectedUsageRunID] = useState("");
  const [usageSteps, setUsageSteps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [selectedProviderID, setSelectedProviderID] = useState("");
  const [selectedModelID, setSelectedModelID] = useState("");

  const load = async () => {
    setLoading(true); setError("");
    const range = lastDaysRange ? lastDaysRange(7) : {};
    setUsageRange(range);
    const results = await Promise.allSettled([
      api.modelProviders({ limit: 100 }),
      api.modelDefinitions({ limit: 100 }),
      api.modelDeployments({ limit: 100 }),
      api.modelPolicies({ limit: 100 }),
      api.modelPrices({ limit: 100 }),
      api.usageAggregate(range),
      api.usageRuns({ ...range, page: 1, page_size: 20 })
    ]);
    const labels = ["Provider", "Model Definition", "Deployment", "Access Policy", "Price Version", "用量聚合", "用量 Run"];
    const failed = results.map((result, index) => result.status === "rejected" ? labels[index] : "").filter(Boolean);
    const values = results.map((result) => result.status === "fulfilled" ? result.value : []);
    const models = itemsOf(values[1]);
    const versionResults = await Promise.allSettled(models.map((model) => api.modelDefinitionVersions(model.id, { limit: 100 })));
    const versions = versionResults.flatMap((result, index) => result.status === "fulfilled" ? itemsOf(result.value).map((version) => ({ ...version, definition_id: version.definition_id || models[index].id })) : []);
    const usageRuns = itemsOf(values[6]);
    setData({
      usage: values[5] && !Array.isArray(values[5]) ? values[5] : null,
      usageRuns,
      providers: itemsOf(values[0]),
      models,
      versions,
      prices: itemsOf(values[4]),
      deployments: itemsOf(values[2]),
      policies: itemsOf(values[3])
    });
    if (usageRuns.length && !selectedUsageRunID) setSelectedUsageRunID(usageRuns[0].run_id);
    if (failed.length) setNotice(`${failed.join("、")} 查询失败；其余治理数据仍可查看。`);
    setLoading(false);
  };
  useEffect(() => { load(); }, []);
  useEffect(() => {
    let active = true;
    setUsageSteps([]);
    if (!selectedUsageRunID) return () => { active = false; };
    api.usageRunSteps(selectedUsageRunID, usageRange)
      .then((result) => { if (active) setUsageSteps(itemsOf(result)); })
      .catch(() => { if (active) setUsageSteps([]); });
    return () => { active = false; };
  }, [selectedUsageRunID, usageRange]);

  const providers = data.providers;
  const selectedProvider = providers.find((item) => item.id === selectedProviderID) || null;
  const selectedModel = data.models.find((item) => item.id === selectedModelID) || null;
  const tokens = Number(data.usage?.input_tokens || 0) + Number(data.usage?.output_tokens || 0);
  const approvedProviders = providers.filter((item) => item.status === "approved").length;
  const readyDeployments = data.deployments.filter((item) => item.status === "ready" || item.health_status === "ready").length;

  const action = async (work, message) => {
    setBusy(true); setError(""); setNotice("");
    // Reload first, then publish the action result: load() may set its own
    // "query failed" notice, which must not shadow the success message the
    // operator just earned.
    // 先刷新再展示动作结果：load() 可能写入“查询失败”提示，不能覆盖操作者刚获得的成功提示。
    try { await work(); await load(); setNotice(message); }
    catch (reason) { setError(reason.code === "40903" || reason.code === "REVISION_CONFLICT" ? "资源已被其他管理员修改，请刷新后重试。" : reason.message || "操作失败"); }
    finally { setBusy(false); }
  };
  const submit = async (event, work, message) => {
    event.preventDefault();
    // React nulls SyntheticEvent.currentTarget once the handler returns, so any
    // read after `await` is null and a later reset() throws. Capture the form
    // synchronously and reuse that reference for both FormData and reset.
    // React 在事件处理函数返回后会把 SyntheticEvent.currentTarget 置空，await 之后
    // 再读取即为 null，随后的 reset() 会抛错。这里同步捕获表单引用，供 FormData 与
    // reset 复用。
    const form = event.currentTarget;
    setBusy(true); setError(""); setNotice("");
    try { await work(new FormData(form), form); form.reset(); await load(); setNotice(message); }
    catch (reason) { setError(reason.message || "操作失败"); }
    finally { setBusy(false); }
  };

  const createProvider = (event) => submit(event, (form) => api.createModelProvider({ provider_key: form.get("provider_key"), display_name: form.get("display_name"), type: form.get("type"), trust_zone: form.get("trust_zone"), endpoint_ref: form.get("endpoint_ref"), network_zone: form.get("network_zone"), region: form.get("region"), secret_ref: form.get("secret_ref"), retention_mode: form.get("retention_mode"), training_usage: form.get("training_usage"), compliance_status: form.get("compliance_status"), capabilities: parseObject(form.get("capabilities"), "Capabilities") }), "Provider 已登记为 draft");
  const createModel = (event) => submit(event, (form) => api.createModelDefinition({ provider_id: form.get("provider_id"), model_key: form.get("model_key"), kind: form.get("kind"), display_name: form.get("display_name"), context_limit: Number(form.get("context_limit")), capabilities: parseObject(form.get("capabilities"), "Capabilities") }), "Model Definition 已登记");
  const createVersion = (event) => submit(event, (form) => api.createModelDefinitionVersion(form.get("definition_id"), { semantic_version: form.get("semantic_version"), provider_fingerprint: form.get("provider_fingerprint"), artifact_digest: form.get("artifact_digest"), quantization: form.get("quantization"), capability_hash: form.get("capability_hash") }), "Model Version 已登记为 draft");
  const createDeployment = (event) => submit(event, (form) => api.createModelDeployment({ model_version_id: form.get("model_version_id"), environment: form.get("environment"), endpoint_ref: form.get("endpoint_ref"), runtime_kind: form.get("runtime_kind"), min_replicas: Number(form.get("min_replicas")), max_replicas: Number(form.get("max_replicas")), resource_profile: parseObject(form.get("resource_profile"), "Resource Profile"), capacity: parseObject(form.get("capacity"), "Capacity") }), "Model Deployment 期望配置已登记；本操作不会直接创建 Kubernetes 工作负载。");
  const createPolicy = (event) => submit(event, (form, node) => api.createModelPolicy({ department_id: form.get("department_id"), application_id: form.get("application_id"), installation_id: form.get("installation_id"), agent_version_id: form.get("agent_version_id"), principal_id: form.get("principal_id"), allow_local: node.elements.allow_local.checked, allow_private: node.elements.allow_private.checked, allow_external: node.elements.allow_external.checked, allowed_providers: String(form.get("allowed_providers") || "").split(",").map((value) => value.trim()).filter(Boolean), allowed_models: String(form.get("allowed_models") || "").split(",").map((value) => value.trim()).filter(Boolean) }), "Model Access Policy 已创建为 draft");
  const createPrice = (event) => submit(event, (form) => {
    const until = String(form.get("effective_until") || "");
    return api.createModelPrice({
      model_version_id: form.get("model_version_id"),
      currency: form.get("currency"),
      input_micros_per_1k_tokens: Number(form.get("input_micros_per_1k_tokens")),
      output_micros_per_1k_tokens: Number(form.get("output_micros_per_1k_tokens")),
      effective_from: new Date(String(form.get("effective_from"))).toISOString(),
      ...(until ? { effective_until: new Date(until).toISOString() } : {})
    });
  }, "价格版本已登记为 draft；批准后按生效区间供服务端解析。");

  if (loading) return <Localized><div className="state-panel"><span className="spinner"/><p>正在读取模型治理控制面</p></div></Localized>;

  return <Localized><>
    <BillingReconciliation />
    <div className="page-title"><div><p className="eyebrow">模型与用量</p><h2>大模型治理中心</h2><p>管理 Provider、Model Definition/Version、价格版本、Deployment 与 Model Access Policy；用量查询读取持久化账本。预算配置与阈值告警仍待接入。</p></div><button className="button secondary" onClick={load}>刷新治理数据</button></div>
    {notice && <div className="success-banner">{notice}</div>}{error && <div className="form-error page-error">{error}</div>}
    <section className="metric-grid"><article className="metric violet"><span>Provider</span><strong>{approvedProviders}/{providers.length}</strong><small>已批准 / 总数</small></article><article className="metric"><span>Model Definition / Version</span><strong>{data.models.length} / {data.versions.length}</strong><small>模块化模型目录</small></article><article className="metric green"><span>Deployment</span><strong>{readyDeployments}/{data.deployments.length}</strong><small>服务端观测状态 / 总数</small></article><article className="metric cyan"><span>近 7 日 Token</span><strong>{tokens}</strong><small>持久用量账本</small></article></section>

    <section className="two-column"><article className="card"><div className="card-heading"><div><h3>Provider Registry</h3><p className="form-hint">只保存 SecretRef；外部 Endpoint 必须由服务端做 SSRF 和网络区校验。</p></div><span>{providers.length} 个</span></div>{providers.length ? <div className="record-list">{providers.map((provider) => <div key={provider.id}><button type="button" className="record-icon" onClick={() => setSelectedProviderID(provider.id)}>{selectedProvider?.id === provider.id ? "✓" : "P"}</button><span><b>{provider.display_name} · {provider.provider_key}</b><small>{provider.type} / {provider.trust_zone} · {provider.endpoint_ref}</small><small>SecretRef：{provider.secret_ref || "—"} · 健康 {provider.health_status} · r{provider.revision}</small></span><div className="inline-actions"><span className={`badge ${statusTone(provider.status)}`}>{formatStatus(provider.status)}</span>{provider.status === "draft" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.testModelProvider(provider.id), "Provider Endpoint 安全校验已完成")}>测试</button>}{provider.status === "draft" && <button className="button primary" disabled={busy} onClick={() => action(() => api.approveModelProvider(provider.id, provider.revision), "Provider 已批准")}>批准</button>}{provider.status === "approved" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.disableModelProvider(provider.id, provider.revision), "Provider 已停用")}>停用</button>}</div></div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Provider</b><p>先登记本地、私有云或外部 Provider，再登记其 Model Version。</p></div>}</article>
      <article className="card"><div className="card-heading"><div><h3>登记 Provider</h3><p className="form-hint">全局资产由平台管理员登记，所有者取当前登录身份；只填写 SecretRef，不填写 API Key。</p></div></div><form className="form" onSubmit={createProvider}><div className="inline-form"><label><span>Provider Key</span><input name="provider_key" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}" placeholder="local-qwen" required/></label><label><span>显示名称</span><input name="display_name" placeholder="Local Qwen" required/></label></div><div className="inline-form"><label><span>类型</span><select name="type" defaultValue="on_prem"><option value="on_prem">on_prem</option><option value="private_cloud">private_cloud</option><option value="external_managed">external_managed</option></select></label><label><span>信任域</span><select name="trust_zone" defaultValue="local"><option value="local">local</option><option value="private">private</option><option value="external">external</option></select></label></div><label><span>Provider EndpointRef</span><input name="endpoint_ref" pattern="(service|k8s|ref)://.+" title="必须使用服务端已配置的 service://、k8s:// 或 ref:// 符号引用" placeholder="service://providers/local-qwen" required/></label><p className="form-hint">EndpointRef 不是 URL。运维需在平台服务端的 PLATFORM_MODEL_ENDPOINTS_JSON 中维护符号引用到真实 HTTPS Endpoint 的映射；未映射时 Provider 测试会失败关闭。</p><div className="inline-form"><input name="network_zone" placeholder="internal / egress-approved" required/><input name="region" placeholder="cn-east-1" required/></div><input name="secret_ref" defaultValue="secret://model-provider/local-qwen" pattern="(secret|file)://.+" required/><div className="inline-form"><label><span>留存声明</span><select name="retention_mode" defaultValue="provider_defined"><option value="provider_defined">provider_defined</option><option value="none">none</option><option value="limited">limited</option></select></label><label><span>训练使用</span><select name="training_usage" defaultValue="unknown"><option value="unknown">unknown</option><option value="none">none</option><option value="opt_in">opt_in</option></select></label></div><input name="compliance_status" defaultValue="pending" placeholder="pending / approved" required/><label><span>Capabilities JSON</span><textarea name="capabilities" defaultValue='{"chat":true,"streaming":true}' rows={3} spellCheck="false"/></label><button className="button primary" disabled={busy}>登记 Provider</button></form></article></section>

    <section className="two-column"><article className="card"><div className="card-heading"><div><h3>Model Definition Registry</h3><p className="form-hint">模型目录从持久化 Definition/Version 查询；版本必须有稳定 fingerprint，别名不能静默替换制品。</p></div><span>{data.models.length} 个 Definition</span></div><form className="form" onSubmit={createModel}><label><span>Provider</span><select name="provider_id" value={selectedProviderID} onChange={(event) => setSelectedProviderID(event.target.value)} required><option value="" disabled>选择已批准 Provider</option>{providers.filter((item) => item.status === "approved").map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.provider_key}</option>)}</select></label><div className="inline-form"><input name="model_key" placeholder="qwen2.5-7b-instruct" required/><input name="display_name" placeholder="Qwen 2.5 7B" required/></div><div className="inline-form"><label><span>类型</span><select name="kind" defaultValue="chat"><option value="chat">chat</option><option value="embedding">embedding</option></select></label><label><span>Context Limit</span><input name="context_limit" type="number" min="1" defaultValue="32768" required/></label></div><textarea name="capabilities" defaultValue='{"structured_output":true,"function_calling":true,"streaming":true}' rows={3} spellCheck="false"/><button className="button primary" disabled={busy || !approvedProviders}>登记 Model Definition</button></form>{data.models.length ? <div className="simple-table" style={{ marginTop: 18 }}>{data.models.map((model) => <div key={model.id}><span><b>{model.display_name} · {model.model_key}</b><small>Provider {shortId(model.provider_id)} · {model.kind} · context {model.context_limit}</small></span><span className={`badge ${statusTone(model.lifecycle_status)}`}>{formatStatus(model.lifecycle_status)}</span></div>)}</div> : <div className="empty"><span>◇</span><b>暂无持久化 Model</b><p>Provider 批准后可登记 Model Definition。</p></div>}</article>
      <article className="card"><div className="card-heading"><div><h3>Model Version</h3><p className="form-hint">版本批准使用 revision CAS；本地制品必须填写 Artifact Digest 和量化信息。</p></div><span>{data.versions.length} 个版本</span></div><form className="form" onSubmit={createVersion}><select name="definition_id" value={selectedModelID} onChange={(event) => setSelectedModelID(event.target.value)} required><option value="" disabled>选择 Model Definition</option>{data.models.map((model) => <option key={model.id} value={model.id}>{model.display_name} · {model.model_key}</option>)}</select><input name="semantic_version" pattern="[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9._-]+)?" placeholder="1.0.0" required/><input name="provider_fingerprint" placeholder="sha256:provider-fingerprint" required/><input name="artifact_digest" placeholder="sha256:artifact"/><div className="inline-form"><input name="quantization" placeholder="fp16 / int8"/><input name="capability_hash" placeholder="sha256:capabilities"/></div><button className="button primary" disabled={busy || !data.models.length}>登记 Model Version</button></form>{data.versions.length ? <div className="simple-table" style={{ marginTop: 18 }}>{data.versions.map((version) => <div key={version.id}><span><b>{shortId(version.id)} · {version.semantic_version}</b><small>Definition {shortId(version.definition_id)} · fingerprint {shortId(version.provider_fingerprint, 16)} · {formatStatus(version.status)} · r{version.revision}</small></span>{version.status === "draft" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.approveModelVersion(version.definition_id, version.id, version.revision), "Model Version 已批准")}>批准</button>}</div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Model Version</b><p>创建 Version 后批准，才能登记 Deployment。</p></div>}</article></section>

    <section className="two-column"><article className="card"><div className="card-heading"><div><h3>Model Deployment</h3><p className="form-hint">只引用已批准 Model Version；这里登记期望配置，不直接创建/更新 Kubernetes 工作负载。观测健康由可信服务身份上报，管理员页面只读查看。</p></div><span>{data.deployments.length} 个</span></div><form className="form" onSubmit={createDeployment}><input name="model_version_id" placeholder="Model Version ID" required/><div className="inline-form"><input name="environment" defaultValue="dev" required/><input name="runtime_kind" defaultValue="openai-compatible" required/></div><label><span>Deployment EndpointRef</span><input name="endpoint_ref" pattern="(service|k8s|ref)://.+" title="必须使用服务端已配置的 service://、k8s:// 或 ref:// 符号引用" placeholder="service://models/local-qwen" required/></label><p className="form-hint">EndpointRef 是服务端配置的符号引用，不是直接填写的 URL；运维需在部署/Provider 解析配置中维护引用映射。</p><div className="inline-form"><label><span>最小副本</span><input name="min_replicas" type="number" min="1" defaultValue="1" required/></label><label><span>最大副本</span><input name="max_replicas" type="number" min="1" defaultValue="1" required/></label></div><textarea name="resource_profile" defaultValue='{"cpu":2,"memory_mb":4096}' rows={3} spellCheck="false"/><textarea name="capacity" defaultValue='{"concurrency":8,"tokens_per_second":20}' rows={3} spellCheck="false"/><button className="button primary" disabled={busy}>登记 Deployment 期望配置</button></form>{data.deployments.length ? <div className="simple-table" style={{ marginTop: 18 }}>{data.deployments.map((deployment) => <div key={deployment.id}><span><b>{shortId(deployment.id)} · {deployment.environment}</b><small>Model Version {shortId(deployment.model_version_id)} · {deployment.endpoint_ref} · desired {formatStatus(deployment.status)} · observed health {formatStatus(deployment.health_status)} · status {formatStatus(deployment.status)} · observed revision {deployment.observed_revision ?? "—"} / desired revision {deployment.revision}</small></span></div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Deployment</b><p>批准 Model Version 后可登记部署期望配置。</p></div>}</article>
      <article className="card"><div className="card-heading"><div><h3>Model Access Policy</h3><p className="form-hint">当前策略仅控制信任域、允许的 Provider/Model 与作用范围。Token/金额预算、数据等级策略未接入本模块。</p></div><span>{data.policies.length} 条</span></div><form className="form" onSubmit={createPolicy}><div className="inline-form"><input name="department_id" placeholder="Department ID（可选）"/><input name="application_id" placeholder="Application ID（可选）"/></div><div className="inline-form"><input name="installation_id" placeholder="Installation ID（可选）"/><input name="agent_version_id" placeholder="Agent Version ID（可选）"/></div><input name="principal_id" placeholder="Principal / Service Principal（可选）"/><div className="inline-actions"><label className="checkbox-row"><input name="allow_local" type="checkbox" defaultChecked/><span>允许 local</span></label><label className="checkbox-row"><input name="allow_private" type="checkbox"/><span>允许 private</span></label><label className="checkbox-row"><input name="allow_external" type="checkbox"/><span>允许 external</span></label></div><input name="allowed_providers" placeholder="允许 Provider，逗号分隔"/><input name="allowed_models" placeholder="允许 Model，逗号分隔"/><button className="button primary" disabled={busy}>创建 Access Policy</button></form>{data.policies.length ? <div className="simple-table" style={{ marginTop: 18 }}>{data.policies.map((policy) => <div key={policy.id}><span><b>{shortId(policy.id)} · {policy.installation_id || "应用范围"}</b><small>allow local={String(policy.allow_local)} / private={String(policy.allow_private)} / external={String(policy.allow_external)} · providers={policy.allowed_providers?.join(",") || "*"} · models={policy.allowed_models?.join(",") || "*"}</small></span><div className="inline-actions"><span className={`badge ${statusTone(policy.status)}`}>{formatStatus(policy.status)}</span>{policy.status === "draft" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.approveModelPolicy(policy.id, policy.revision), "Model Access Policy 已批准")}>批准</button>}{policy.status === "approved" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.revokeModelPolicy(policy.id, policy.revision), "Model Access Policy 已撤销")}>撤销</button>}</div></div>)}</div> : <div className="empty"><span>◇</span><b>暂无 Access Policy</b><p>创建策略后，服务端会按可信 Scope 与当前模型治理策略重新判定。</p></div>}</article></section>

    <section className="two-column"><article className="card"><div className="card-heading"><div><h3>Model Price Version</h3><p className="form-hint">价格版本绑定已批准的 Model Version；费率单位是每 1,000 Token 的微单位。批准后不可修改，生效区间不得重叠。</p></div><span>{data.prices.length} 个</span></div><form className="form" onSubmit={createPrice}><label><span>已批准 Model Version</span><select name="model_version_id" required defaultValue=""><option value="" disabled>选择已批准版本</option>{data.versions.filter((version) => version.status === "approved").map((version) => <option key={version.id} value={version.id}>{version.semantic_version} · {shortId(version.id, 18)}</option>)}</select></label><div className="inline-form"><label><span>货币</span><input name="currency" defaultValue="CNY" pattern="[A-Za-z]{3}" maxLength={3} required/></label><label><span>开始生效</span><input name="effective_from" type="datetime-local" required/></label></div><label><span>结束生效（可选）</span><input name="effective_until" type="datetime-local"/></label><div className="inline-form"><label><span>Input micros / 1K Tokens</span><input name="input_micros_per_1k_tokens" type="number" min="0" step="1" required/></label><label><span>Output micros / 1K Tokens</span><input name="output_micros_per_1k_tokens" type="number" min="0" step="1" required/></label></div><button className="button primary" disabled={busy || !data.versions.some((version) => version.status === "approved")}>登记价格版本</button></form>{data.prices.length ? <div className="simple-table" style={{ marginTop: 18 }}>{data.prices.map((price) => <div key={price.id}><span><b>{shortId(price.model_version_id, 18)} · {price.currency}</b><small>Input {price.input_micros_per_1k_tokens} / Output {price.output_micros_per_1k_tokens} micros/1K · {formatTime(price.effective_from)} ～ {price.effective_until ? formatTime(price.effective_until) : "长期"} · r{price.revision}</small></span><div className="inline-actions"><span className={`badge ${statusTone(price.status)}`}>{formatStatus(price.status)}</span>{price.status === "draft" && <button className="button secondary" disabled={busy} onClick={() => action(() => api.approveModelPrice(price.id, price.revision), "价格版本已批准")}>批准</button>}</div></div>)}</div> : <div className="empty"><span>◇</span><b>暂无价格版本</b><p>先批准 Model Version，再登记其费率和生效区间。</p></div>}</article>
      <article className="card"><div className="card-heading"><div><h3>预算与告警</h3><p className="form-hint">当前界面尚无预算配置、阈值通知的后端契约；不能用旧预算 API 代替。</p></div></div><div className="notice warning"><b>全局预算 / 预算阈值告警：当前未接入</b><p>模型费用预算的控制范围、周期、币种与通知渠道仍需与运行期结算完成一致接线后开放管理操作。</p></div></article></section>

    <section className="two-column">
      <article className="card">
        <div className="card-heading"><div><h3>持久用量查询</h3><p className="form-hint">数据来自 Usage 模块的范围授权聚合与 Run 明细；费用单位按台账返回为 micros，不推算模型单价。</p></div></div>
        <div className="version-detail-grid">
          <div><b>事件数</b><small>{data.usage?.event_count ?? "—"}</small></div>
          <div><b>Input / Output Tokens</b><small>{data.usage ? `${data.usage.input_tokens} / ${data.usage.output_tokens}` : "—"}</small></div>
          <div><b>成本微单位</b><small>{data.usage?.cost_micros ?? "—"}</small></div>
        </div>
        <div className="section-heading" style={{ marginTop: 20 }}><div><p className="eyebrow">运行用量</p><h3>运行账目</h3></div><span>{data.usageRuns.length} 条 / 当前页</span></div>
        {data.usageRuns.length ? <div className="record-list">{data.usageRuns.map((run) => <button key={run.run_id} type="button" className="text-button" style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center", gap: 12, padding: "11px 3px", borderBottom: "1px solid #edf0f5", textAlign: "left" }} onClick={() => setSelectedUsageRunID(run.run_id)}><span className="record-icon">$</span><span><b>{shortId(run.run_id, 18)}</b><small>{run.event_count} events · {run.input_tokens} in / {run.output_tokens} out · {run.cost_micros} micros · {formatTime(run.last_usage_at)}</small></span><span className={`badge ${selectedUsageRunID === run.run_id ? "info" : "active"}`}>{selectedUsageRunID === run.run_id ? "已选择" : "明细"}</span></button>)}</div> : <div className="empty"><span>◇</span><b>当前时间范围没有用量 Run</b><p>用量事件写入后会出现在这里。</p></div>}
        {selectedUsageRunID && <div className="simple-table" style={{ marginTop: 16 }}>{usageSteps.length ? usageSteps.map((step) => <div key={step.event_id}><span><b>{step.provider} / {step.model}</b><small>{step.input_tokens} input · {step.output_tokens} output · {step.cost_micros} micros · {formatTime(step.occurred_at)}</small></span><code>{shortId(step.event_id)}</code></div>) : <div><span><b>该 Run 暂无计费步骤或查询不可用</b><small>Usage 明细严格按当前身份作用域过滤。</small></span></div>}</div>}
      </article>
      <article className="card">
        <div className="card-heading"><div><h3>当前未接入的能力</h3><p className="form-hint">界面只暴露已有后端契约，不提交无法兑现的控制命令。</p></div></div>
        <div className="notice warning"><b>预算运行期接线：待验收</b><p>价格目录已可管理，但在价格解析、原子预占、实际结算与通知全链路通过验收前，不声明预算拦截已生效。</p></div>
        <div className="notice" style={{ marginTop: 14 }}><b>部署健康状态由服务端观测</b><p>浏览器可以登记期望部署配置和查看状态，但不能冒充服务身份写入 observed health。</p></div>
      </article>
    </section>
  </></Localized>;
}

export default ModelGovernance;
