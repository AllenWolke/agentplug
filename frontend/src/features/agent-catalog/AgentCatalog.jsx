import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { canSubmitCatalogRelease, canApproveCatalogRelease } from "./release-actions.js";

const manifestTemplate = (agentID, version) => ({
  manifest_version: "agent-manifest/v1",
  agent_id: agentID || "example-agent",
  version: version || "1.0.0",
  execution_protocols: ["agent-execution/v2"],
  capabilities: ["invoke"],
  schemas: {
    input: `schema://${agentID || "example-agent"}/input/v1`,
    output: `schema://${agentID || "example-agent"}/output/v1`,
    event: `schema://${agentID || "example-agent"}/event/v1`,
    checkpoint: `schema://${agentID || "example-agent"}/checkpoint/v1`
  },
  runtime: { transport: "http", isolation: "container", health_path: "/health/ready" }
});

function items(value) { return asItems(value); }
function newID() { return crypto.randomUUID(); }

export function AgentCatalog({ user }) {
  useLanguage();
  const scope = useMemo(() => ({ tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id }), [user.tenant_id, user.department_id, user.application_id]);
  const [definitions, setDefinitions] = useState([]);
  const [installations, setInstallations] = useState([]);
  const [deployments, setDeployments] = useState({});
  const [deploymentVersion, setDeploymentVersion] = useState(null);
  const [versions, setVersions] = useState([]);
  const [grants, setGrants] = useState([]);
  const [selectedDefinition, setSelectedDefinition] = useState("");
  const [selectedInstallation, setSelectedInstallation] = useState("");
  const [decision, setDecision] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [manifestText, setManifestText] = useState(JSON.stringify(manifestTemplate("example-agent", "1.0.0"), null, 2));
  const selectedDefinitionRow = definitions.find((item) => item.id === selectedDefinition);
  const selectedInstall = installations.find((item) => item.id === selectedInstallation);
  const selectedInstallVersionID = selectedInstall?.version_id || "";

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [definitionResult, installationResult] = await Promise.all([
        api.catalogDefinitions({ limit: 100 }),
        api.catalogInstallations(scope)
      ]);
      const nextDefinitions = items(definitionResult);
      const nextInstallations = items(installationResult);
      const deploymentEntries = await Promise.all(nextInstallations.map(async (item) => [
        item.id,
        items(await api.catalogDeployments(item.id, scope)),
      ]));
      setDefinitions(nextDefinitions);
      setInstallations(nextInstallations);
      setDeployments(Object.fromEntries(deploymentEntries));
      setSelectedDefinition((current) => nextDefinitions.some((item) => item.id === current) ? current : (nextDefinitions[0]?.id || ""));
      setSelectedInstallation((current) => nextInstallations.some((item) => item.id === current) ? current : (nextInstallations[0]?.id || ""));
    } catch (reason) {
      setError(reason.message || "无法读取 Agent Catalog");
    } finally {
      setLoading(false);
    }
  }, [scope]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    let active = true;
    if (!selectedDefinition) {
      setVersions([]);
      return () => { active = false; };
    }
    api.catalogDefinitionVersions(selectedDefinition, { limit: 100 })
      .then((result) => { if (active) setVersions(items(result)); })
      .catch((reason) => { if (active) setError(reason.message || "无法读取 Agent Versions"); });
    return () => { active = false; };
  }, [selectedDefinition]);

  useEffect(() => {
    let active = true;
    if (!selectedInstallation) {
      setGrants([]);
      return () => { active = false; };
    }
    api.identityGrants({ agent_instance_id: selectedInstallation })
      .then((result) => { if (active) setGrants(items(result)); })
      .catch((reason) => { if (active) setError(reason.message || "无法读取 Identity Grants"); });
    return () => { active = false; };
  }, [selectedInstallation]);

  useEffect(() => {
    let active = true;
    setDeploymentVersion(null);
    if (!selectedInstallVersionID) return () => { active = false; };
    api.catalogVersion(selectedInstallVersionID)
      .then((version) => { if (active) setDeploymentVersion(version); })
      .catch((reason) => { if (active) setError(reason.message || "无法读取 Installation 当前 Version"); });
    return () => { active = false; };
  }, [selectedInstallVersionID]);

  const publishedVersions = versions.filter((item) => item.status === "published");

  const run = async (work, message) => {
    setError("");
    setNotice("");
    try {
      await work();
      setNotice(message);
      await refresh();
      if (selectedDefinition) {
        const result = await api.catalogDefinitionVersions(selectedDefinition, { limit: 100 });
        setVersions(items(result));
      }
      if (selectedInstallation) {
        const result = await api.identityGrants({ agent_instance_id: selectedInstallation });
        setGrants(items(result));
      }
    } catch (reason) {
      setError(reason.message || "操作失败");
    }
  };

  const createDefinition = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    run(async () => {
      const row = await api.catalogCreateDefinition({ ...values, id: newID(), status: "draft", revision: 1 });
      setSelectedDefinition(row.id);
      form.reset();
    }, "Definition 草稿已创建。请按状态机完成评测和发布。");
  };

  const createVersion = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    run(async () => {
      if (!selectedDefinitionRow) throw new Error("请先选择 Definition");
      const manifest = JSON.parse(values.manifest);
      manifest.agent_id = selectedDefinitionRow.agent_key;
      manifest.version = values.semantic_version;
      await api.catalogCreateVersion(selectedDefinition, {
        id: newID(), definition_id: selectedDefinition, semantic_version: values.semantic_version,
        manifest, artifact_digest: values.artifact_digest,
        input_schema: JSON.parse(values.input_schema), output_schema: JSON.parse(values.output_schema),
        status: "draft", revision: 1
      });
      form.reset();
    }, "不可变 Version 草稿已登记；仍须完成评测和发布后才可安装。");
  };

  const transitionDefinition = (item, action) => run(
    () => api.catalogTransitionDefinition(item.id, action, item.revision),
    action === "evaluate" ? "Definition 已进入 evaluated 状态。" : "Definition 已发布。"
  );

  const transitionVersion = (item, action) => run(
    () => api.catalogTransitionVersion(item.id, action, item.revision),
    action === "evaluate" ? "Version 已进入 evaluated 状态。" : "Version 已发布。"
  );

  const createInstallation = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    run(async () => {
      if (!selectedDefinitionRow || selectedDefinitionRow.status !== "published") throw new Error("Definition 尚未发布");
      const row = await api.catalogCreateInstallation({
        id: newID(), ...scope, agent_id: selectedDefinitionRow.agent_key, version_id: values.version_id,
        display_name: values.display_name, deployment_mode: values.deployment_mode,
        drain_policy: values.drain_policy, retention_policy_id: values.retention_policy_id,
        status: "provisioning", revision: 1
      });
      setSelectedInstallation(row.id);
      form.reset();
    }, "Installation 已创建为 provisioning。确认运行配置后再显式激活。");
  };

  const createDeployment = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    run(async () => {
      if (!selectedInstall || !deploymentVersion || deploymentVersion.id !== selectedInstall.version_id) {
        throw new Error("必须读取到 Installation 当前绑定的精确 Version 后才能创建 Deployment");
      }
      await api.catalogCreateDeployment(selectedInstall.id, {
        id: newID(), tenant_id: selectedInstall.tenant_id, department_id: selectedInstall.department_id,
        application_id: selectedInstall.application_id, agent_version_id: selectedInstall.version_id,
        agent_installation_id: selectedInstall.id, artifact_digest: deploymentVersion.artifact_digest,
        manifest_hash: deploymentVersion.manifest_hash, transport: values.transport,
        endpoint_ref: values.endpoint_ref, placement_policy: JSON.parse(values.placement_policy),
        resource_policy: JSON.parse(values.resource_policy), status: "pending", desired_revision: 0
      });
      form.reset();
    }, "Deployment 期望状态已创建；健康结果由运行控制面观测，不可由浏览器伪造。");
  };

  const createGrant = (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    run(async () => {
      if (!selectedInstall) throw new Error("请选择 Installation");
      await api.createIdentityGrant({
        id: newID(), tenant_id: selectedInstall.tenant_id, department_id: selectedInstall.department_id,
        application_id: selectedInstall.application_id, agent_instance_id: selectedInstall.id,
        subject_type: values.subject_type, subject_id: values.subject_id, action: values.action,
        effect: values.effect, status: "active", revision: 1
      });
      form.reset();
    }, "Identity Grant 已保存；运行授权仍由服务端重新判定。");
  };

  const explainGrant = (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    run(async () => {
      if (!selectedInstall) throw new Error("请选择 Installation");
      const result = await api.identityExplainGrant({
        scope: { ...scope, agent_instance_id: selectedInstall.id },
        principal_type: values.subject_type, principal_id: values.subject_id, action: values.action
      });
      setDecision(result);
    }, "Identity 已使用运行时相同的授权规则完成解释。");
  };

  const installationTransition = (item, from, to) => run(
    () => api.catalogTransitionInstallation(item.id, from, to, item.revision),
    `Installation 状态已更新为 ${to}。`
  );

  const uninstall = (item) => run(
    () => api.catalogUninstallInstallation(item.id, item.revision),
    "卸载已启动；排空和资源回收后再确认终态。"
  );

  const revokeGrant = (grant) => run(
    () => api.revokeIdentityGrant(grant.id, { ...scope, agent_instance_id: selectedInstall.id }, grant.revision),
    "Grant 已撤销，新请求将立即按最新状态重新判定。"
  );

  if (loading && definitions.length === 0) return <Localized><div className="state-panel"><p>正在读取 Agent Catalog…</p></div></Localized>;
  return <Localized><main className="agent-catalog-page">
    <header className="page-title"><div><p className="eyebrow">助手目录与安装</p><h2>可插拔 Agent 治理</h2><p>通过唯一 Catalog 契约登记不可变 Manifest、评测发布版本，并安装到当前应用。身份和授权由 Identity 模块判定。</p></div><button className="button secondary" onClick={refresh}>刷新</button></header>
    {notice && <div className="success-banner">{notice}</div>}{error && <div className="form-error page-error">{error}</div>}
    <section className="metric-grid"><article className="metric"><span>全局 Definition</span><strong>{definitions.length}</strong><small>平台目录；平台管理员治理</small></article><article className="metric violet"><span>当前应用 Installation</span><strong>{installations.length}</strong><small>{scope.tenant_id} / {scope.application_id}</small></article><article className="metric green"><span>执行协议</span><strong>HTTP / gRPC</strong><small>版本 Manifest 固化</small></article><article className="metric cyan"><span>默认权限</span><strong>Deny</strong><small>服务端 Identity 判定</small></article></section>
    <section className="two-column">
      <article className="card"><h3>1. 注册 Agent Definition</h3><form className="form" onSubmit={createDefinition}><input name="agent_key" placeholder="稳定 Agent Key" required/><input name="publisher_id" defaultValue="platform" placeholder="Publisher ID" required/><input name="display_name" placeholder="显示名称" required/><textarea name="description" placeholder="能力边界" required/><button className="button primary" disabled={!canSubmitCatalogRelease(user)}>创建 Definition 草稿</button></form><div className="record-list">{definitions.map((item) => <div className="catalog-row" key={item.id}><button className="link-button" onClick={() => setSelectedDefinition(item.id)}><b>{item.display_name}</b><small>{item.agent_key} · r{item.revision}</small><small>提交人：{item.submitted_by || "历史来源待核实"} · 批准人：{item.approved_by || "尚未批准"}</small><small>{item.description}</small></button><span className="badge">{item.status}</span>{item.status === "draft" && <button className="button secondary" onClick={() => transitionDefinition(item, "evaluate")}>评测 Definition</button>}{canApproveCatalogRelease(user, item) && <button className="button primary" onClick={() => transitionDefinition(item, "publish")}>发布 Definition</button>}</div>)}</div></article>
      <article className="card"><h3>2. 创建完整不可变 Version</h3><label><span>Definition</span><select value={selectedDefinition} onChange={(event) => { setSelectedDefinition(event.target.value); const row = definitions.find((item) => item.id === event.target.value); setManifestText(JSON.stringify(manifestTemplate(row?.agent_key, "1.0.0"), null, 2)); }}><option value="">选择 Definition</option>{definitions.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.agent_key}</option>)}</select></label><form className="form" onSubmit={createVersion}><input name="semantic_version" placeholder="1.0.0" required/><input name="artifact_digest" pattern="sha256:[0-9a-f]{64}" placeholder="sha256:<64位镜像/制品摘要>" required/><label><span>Manifest JSON（Agent ID/版本号由服务端绑定）</span><textarea name="manifest" value={manifestText} onChange={(event) => setManifestText(event.target.value)} required rows="7"/></label><label><span>Input JSON Schema</span><textarea name="input_schema" defaultValue={'{"type":"object"}'} required rows="3"/></label><label><span>Output JSON Schema</span><textarea name="output_schema" defaultValue={'{"type":"object"}'} required rows="3"/></label><button className="button primary" disabled={!selectedDefinition || !canSubmitCatalogRelease(user)}>创建 Version 草稿</button></form></article>
    </section>
    <section className="card"><header className="card-heading"><h3>3. Version 评测与发布</h3><span>{versions.length} 个不可变版本</span></header>{versions.length ? <div className="record-list">{versions.map((item) => <div className="catalog-row" key={item.id}><span><b>{item.semantic_version}</b><small>{item.id}</small><small>Manifest SHA-256：{item.manifest_hash}</small><small>Artifact：{item.artifact_digest}</small><small>提交人：{item.submitted_by || "历史来源待核实"} · 批准人：{item.approved_by || "尚未批准"}</small></span><span className="badge">{item.status}</span>{item.status === "draft" && <button className="button secondary" onClick={() => transitionVersion(item, "evaluate")}>评测 Version</button>}{canApproveCatalogRelease(user, item) && <button className="button primary" onClick={() => transitionVersion(item, "publish")}>发布 Version</button>}</div>)}</div> : <div className="empty"><b>暂无版本</b><p>选择 Definition 并创建 Version 草稿。</p></div>}</section>
    <section className="two-column">
      <article className="card"><h3>4. 安装已发布 Agent 到当前应用</h3><form className="form" onSubmit={createInstallation}><label><span>已发布 Definition Version</span><select name="version_id" required defaultValue=""><option value="">选择已发布版本</option>{selectedDefinitionRow?.status === "published" && publishedVersions.map((item) => <option key={item.id} value={item.id}>{selectedDefinitionRow.display_name} · {item.semantic_version}</option>)}</select></label><input name="display_name" placeholder="应用内显示名称" required/><label><span>部署模式</span><select name="deployment_mode" defaultValue="managed"><option value="managed">平台托管</option><option value="external">外部 Adapter</option></select></label><label><span>排空策略</span><select name="drain_policy" defaultValue="wait"><option value="wait">等待运行完成</option><option value="cancel">取消运行</option></select></label><input name="retention_policy_id" defaultValue="default" required/><button className="button primary" disabled={selectedDefinitionRow?.status !== "published" || publishedVersions.length === 0}>创建 Installation</button></form>{(selectedDefinitionRow?.status !== "published" || publishedVersions.length === 0) && <p className="form-hint">必须先发布 Definition 和至少一个 Version。</p>}</article>
      <article className="card"><h3>当前应用 Installations</h3><div className="record-list">{installations.map((item) => { const latest = deployments[item.id]?.[0]; const ready = latest?.status === "ready" && latest.observed_revision === latest.desired_revision && latest.agent_version_id === item.version_id; return <div className="catalog-row" key={item.id}><button className="link-button" onClick={() => setSelectedInstallation(item.id)}><b>{item.display_name}</b><small>{item.agent_id} · {item.version_id} · r{item.revision}</small><small>{item.deployment_mode} · drain={item.drain_policy} · retention={item.retention_policy_id}</small>{latest && <small>Deployment：{latest.status} · {latest.observed_revision}/{latest.desired_revision}</small>}</button><span className="badge">{item.status}</span>{item.status === "provisioning" && <button className="button primary" disabled={!ready} onClick={() => installationTransition(item, "provisioning", "active")}>激活</button>}{item.status === "active" && <button className="button secondary" onClick={() => installationTransition(item, "active", "suspended")}>暂停</button>}{item.status === "suspended" && <button className="button secondary" disabled={!ready} onClick={() => installationTransition(item, "suspended", "active")}>恢复</button>}{["active", "suspended", "draining"].includes(item.status) && <button className="button secondary danger" onClick={() => uninstall(item)}>开始卸载</button>}{item.status === "uninstalling" && <button className="button secondary" onClick={() => installationTransition(item, "uninstalling", "uninstalled")}>确认卸载完成</button>}</div>; })}</div>{installations.length === 0 && <div className="empty"><b>当前应用尚无 Agent</b><p>只有已发布的 Definition 和 Version 可以安装。</p></div>}</article>
    </section>
    <section className="two-column"><article className="card"><h3>5. 平台部署控制</h3><p className="form-hint">只有平台/系统管理员可写入当前 Installation 的期望部署配置；Revision 由 Catalog 按安装行锁定分配，浏览器不能伪造 Ready。</p><form className="form" onSubmit={createDeployment}><label><span>目标 Installation</span><select value={selectedInstallation} onChange={(event) => setSelectedInstallation(event.target.value)} required><option value="">选择当前作用域 Installation</option>{installations.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.id} · {item.status}</option>)}</select></label><label><span>Transport</span><select name="transport" defaultValue="http"><option value="http">HTTP</option><option value="grpc">gRPC</option></select></label><input name="endpoint_ref" placeholder="https://agent.internal 或 dns://service:port" required maxLength="512"/><label><span>Placement Policy JSON</span><textarea name="placement_policy" defaultValue='{"mode":"managed","replicas":1}' rows="3" required/></label><label><span>Resource Policy JSON</span><textarea name="resource_policy" defaultValue='{"cpu":"100m","memory":"128Mi"}' rows="3" required/></label><button className="button primary" disabled={!selectedInstall || !deploymentVersion || !["provisioning", "suspended", "active"].includes(selectedInstall.status)}>创建 Deployment Revision</button></form>{!selectedInstall && <p className="form-hint">当前应用尚无可部署 Installation。</p>}</article><article className="card"><h3>Deployment 观测状态</h3>{selectedInstall ? <><p>{selectedInstall.display_name} · {selectedInstall.version_id}</p><div className="record-list">{(deployments[selectedInstall.id] || []).map((deployment) => <div className="catalog-row" key={deployment.id}><span><b>{deployment.status} · desired r{deployment.desired_revision}</b><small>{deployment.id} · {deployment.transport} · {deployment.endpoint_ref}</small><small>observed r{deployment.observed_revision} · Version {deployment.agent_version_id}</small></span><span className="badge">{deployment.status === "ready" && deployment.observed_revision === deployment.desired_revision ? "Ready" : "等待观测"}</span></div>)}</div>{!(deployments[selectedInstall.id] || []).length && <div className="empty"><b>尚无 Deployment</b><p>创建期望部署后，由受信任的运行控制面报告健康状态。</p></div>}</> : <div className="empty"><b>选择 Installation 查看部署</b><p>Ready 观测只接受运行控制面调用。</p></div>}</article></section>
    <section className="two-column"><article className="card"><h3>5. 细粒度 Identity Grant</h3><label><span>Installation</span><select value={selectedInstallation} onChange={(event) => { setSelectedInstallation(event.target.value); setDecision(null); }}><option value="">选择当前应用 Installation</option>{installations.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.id}</option>)}</select></label><form className="form" onSubmit={createGrant}><label><span>主体类型</span><select name="subject_type" defaultValue="user"><option value="user">用户</option><option value="service_principal">机器身份</option></select></label><input name="subject_id" placeholder="主体 ID" required/><label><span>授权动作</span><select name="action" defaultValue="run"><option value="discover">discover</option><option value="invoke">invoke</option><option value="run">run</option><option value="resume">resume</option><option value="cancel">cancel</option><option value="events">events</option></select></label><label><span>效果</span><select name="effect" defaultValue="allow"><option value="allow">允许</option><option value="deny">拒绝</option></select></label><button className="button primary" disabled={!selectedInstall}>保存 Grant</button></form><div className="record-list">{grants.map((grant) => <div className="catalog-row" key={grant.id}><span><b>{grant.subject_type} · {grant.subject_id}</b><small>{grant.action} · {grant.effect} · r{grant.revision}</small></span><span className="badge">{grant.status}</span>{grant.status === "active" && <button className="button secondary" onClick={() => revokeGrant(grant)}>撤销</button>}</div>)}</div></article>
      <article className="card"><h3>6. 服务端授权 Explain</h3><form className="form" onSubmit={explainGrant}><label><span>主体类型</span><select name="subject_type" defaultValue="user"><option value="user">用户</option><option value="service_principal">机器身份</option></select></label><input name="subject_id" placeholder="主体 ID" required/><label><span>请求动作</span><select name="action" defaultValue="run"><option value="discover">discover</option><option value="invoke">invoke</option><option value="run">run</option><option value="resume">resume</option><option value="cancel">cancel</option><option value="events">events</option></select></label><button className="button secondary" disabled={!selectedInstall}>解释授权</button></form>{decision && <div className="notice"><b>{decision.allowed ? "ALLOW" : "DENY"}</b><p>{decision.reason || "默认拒绝"}</p></div>}<p className="form-hint">当前 scope：{scope.tenant_id} / {scope.department_id} / {scope.application_id}。此操作仅解释当前 Installation，权限仍在运行时重新校验。</p></article></section>
  </main></Localized>;
}
