import { Localized, useLanguage } from "../../components/Localization.jsx";
import { translateUI } from "../../localization.js";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { applicationInstallationCommand } from "../identity/application-installation-command.js";
import { publishedRollbackOptions } from "./rollback-options.js";

const newID = () => crypto.randomUUID();

// Application admins can install published Agents, but cannot create or publish global definitions.
// 应用管理员可以安装已发布 Agent，但不能创建或发布全局 Definition。
export function ApplicationAgentInstallations({ user }) {
  useLanguage();
  const scope = useMemo(() => ({
    tenant_id: user.tenant_id,
    department_id: user.department_id,
    application_id: user.application_id
  }), [user.tenant_id, user.department_id, user.application_id]);
  const [definitions, setDefinitions] = useState([]);
  const [installations, setInstallations] = useState([]);
  const [deployments, setDeployments] = useState({});
  const [versions, setVersions] = useState([]);
  const [definitionID, setDefinitionID] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rollbackInstallationID, setRollbackInstallationID] = useState("");
  const [rollbackOptions, setRollbackOptions] = useState([]);
  const [rollbackVersionID, setRollbackVersionID] = useState("");
  const [rollbackLoading, setRollbackLoading] = useState(false);
  const [rollbackBusy, setRollbackBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [available, current] = await Promise.all([
        api.catalogAvailableDefinitions(scope),
        api.catalogInstallations(scope)
      ]);
      const nextDefinitions = asItems(available);
      const nextInstallations = asItems(current);
      const pendingLifecycle = nextInstallations.filter((item) => ["provisioning", "suspended"].includes(item.status));
      const deploymentEntries = await Promise.all(pendingLifecycle.map(async (item) => [
        item.id,
        asItems(await api.catalogDeployments(item.id, scope)),
      ]));
      setDefinitions(nextDefinitions);
      setInstallations(nextInstallations);
      setDeployments(Object.fromEntries(deploymentEntries));
      const installedAgents = new Set(nextInstallations.map((item) => item.agent_id));
      const installable = nextDefinitions.filter((item) => !installedAgents.has(item.agent_key));
      setDefinitionID((currentID) => installable.some((item) => item.id === currentID) ? currentID : (installable[0]?.id || ""));
    } catch (reason) {
      setError(reason.message || "无法读取当前应用可安装的 Agent");
    } finally {
      setLoading(false);
    }
  }, [scope]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    let active = true;
    setVersions([]);
    if (!definitionID) return () => { active = false; };
    api.catalogAvailableDefinitionVersions(definitionID, scope)
      .then((result) => { if (active) setVersions(asItems(result)); })
      .catch((reason) => { if (active) setError(reason.message || "无法读取已发布 Agent 版本"); });
    return () => { active = false; };
  }, [definitionID, scope]);

  const selectedDefinition = definitions.find((item) => item.id === definitionID);
  const installedAgents = new Set(installations.map((item) => item.agent_id));
  const installableDefinitions = definitions.filter((item) => !installedAgents.has(item.agent_key));
  const install = async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const version = versions.find((item) => item.id === values.version_id);
      const command = applicationInstallationCommand(values, user, selectedDefinition, version, newID());
      await api.catalogCreateInstallation(command);
      setNotice("Agent Installation 已创建为 provisioning；部署就绪后再激活。");
      form.reset();
      await refresh();
      window.dispatchEvent(new Event("agent-catalog-changed"));
    } catch (reason) {
      setError(reason.message || "创建 Agent Installation 失败");
    } finally {
      setSaving(false);
    }
  };

  const transition = async (installation, to) => {
    setError("");
    setNotice("");
    try {
      await api.catalogTransitionInstallation(installation.id, installation.status, to, installation.revision);
      setNotice(`Installation 状态已更新为 ${to}。`);
      await refresh();
      window.dispatchEvent(new Event("agent-catalog-changed"));
    } catch (reason) {
      setError(reason.message || "更新 Agent Installation 失败");
      await refresh();
    }
  };

  const uninstall = async (installation) => {
    setError("");
    setNotice("");
    try {
      await api.catalogUninstallInstallation(installation.id, installation.revision);
      setNotice("卸载流程已启动；排空完成后由部署控制面确认最终状态。");
      await refresh();
      window.dispatchEvent(new Event("agent-catalog-changed"));
    } catch (reason) {
      setError(reason.message || "启动 Agent 卸载失败");
      await refresh();
    }
  };

  const toggleRollback = async (installation) => {
    if (rollbackInstallationID === installation.id) {
      setRollbackInstallationID("");
      setRollbackOptions([]);
      setRollbackVersionID("");
      return;
    }
    const definition = definitions.find((item) => item.agent_key === installation.agent_id);
    if (!definition) {
      setError("无法在当前应用目录中解析该 Agent Definition，已拒绝加载回滚目标");
      return;
    }
    setRollbackInstallationID(installation.id);
    setRollbackOptions([]);
    setRollbackVersionID("");
    setRollbackLoading(true);
    setError("");
    try {
      const result = await api.catalogAvailableDefinitionVersions(definition.id, scope);
      const options = publishedRollbackOptions(asItems(result), installation.version_id);
      setRollbackOptions(options);
      setRollbackVersionID(options[0]?.id || "");
    } catch (reason) {
      setError(reason.message || "无法读取该 Agent 的已发布回滚版本");
    } finally {
      setRollbackLoading(false);
    }
  };

  const rollback = async (installation) => {
    const target = rollbackOptions.find((item) => item.id === rollbackVersionID);
    if (!target || !["active", "suspended"].includes(installation.status)) {
      setError("请选择同一 Agent 的其他已发布版本，并确认 Installation 处于可回滚状态");
      return;
    }
    if (!window.confirm(translateUI(`确认将 ${installation.display_name} 回滚到 ${target.semantic_version}？`))) return;
    setRollbackBusy(true);
    setError("");
    setNotice("");
    try {
      await api.catalogRollbackInstallation(installation.id, target.id, installation.revision);
      setNotice(`Installation 已切换到 ${target.semantic_version}；请平台管理员为该版本创建 Deployment 并由运行控制面确认 Ready。`);
      setRollbackInstallationID("");
      setRollbackOptions([]);
      setRollbackVersionID("");
      await refresh();
      window.dispatchEvent(new Event("agent-catalog-changed"));
    } catch (reason) {
      setError(reason.message || "Agent 回滚失败；请刷新 Installation revision 后重试");
      await refresh();
    } finally {
      setRollbackBusy(false);
    }
  };

  return <Localized><section className="card application-agent-installations">
    <div className="card-heading">
      <div><h3>当前应用 Agent 安装</h3><p>只能选择平台已发布的 Definition/Version；安装作用域始终来自当前登录账号。</p></div>
      <button className="button secondary" type="button" onClick={refresh} disabled={loading}>刷新</button>
    </div>
    {notice && <div className="success-banner" role="status">{notice}</div>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {loading ? <p>正在读取可安装 Agent…</p> : <>
      <form className="form" onSubmit={install}>
        <label><span>已发布 Agent</span><select value={definitionID} onChange={(event) => setDefinitionID(event.target.value)} required>
          <option value="">选择已发布 Agent</option>
          {installableDefinitions.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.agent_key}</option>)}
        </select></label>
        <label><span>已发布 Version</span><select name="version_id" required defaultValue="">
          <option value="">选择版本</option>
          {versions.map((item) => <option key={item.id} value={item.id}>{item.semantic_version} · {item.id}</option>)}
        </select></label>
        <input name="display_name" placeholder="应用内显示名称" required maxLength="160" />
        <label><span>部署模式</span><select name="deployment_mode" defaultValue="managed"><option value="managed">平台托管</option><option value="external">外部 Adapter</option></select></label>
        <label><span>排空策略</span><select name="drain_policy" defaultValue="wait"><option value="wait">等待运行完成</option><option value="cancel">取消运行</option></select></label>
        <input name="retention_policy_id" defaultValue="default" required maxLength="128" />
        <button className="button primary" disabled={saving || !selectedDefinition || versions.length === 0}>{saving ? "正在创建…" : "创建 Agent Installation"}</button>
      </form>
      {installableDefinitions.length === 0 && <p className="form-hint">当前没有可新增的已发布 Agent。可能尚无平台发布项，或这些 Agent 已安装在本应用中。</p>}
      <div className="record-list">{installations.map((item) => {
        const latestDeployment = deployments[item.id]?.[0];
        const deploymentReady = latestDeployment?.status === "ready" &&
          latestDeployment.observed_revision === latestDeployment.desired_revision &&
          latestDeployment.agent_version_id === item.version_id;
        return <div className="catalog-row" key={item.id}>
        <span><b>{item.display_name}</b><small>{item.agent_id} · {item.version_id} · {item.id}</small><small>{item.deployment_mode} · revision {item.revision}</small>
          {latestDeployment && <small>最新部署：{latestDeployment.status} · revision {latestDeployment.observed_revision}/{latestDeployment.desired_revision}</small>}
        </span>
        <span className="badge">{item.status}</span>
        {item.status === "provisioning" && <button className="button primary" type="button" onClick={() => transition(item, "active")} disabled={!deploymentReady}>确认部署就绪并激活</button>}
        {item.status === "active" && <button className="button secondary" type="button" onClick={() => transition(item, "suspended")}>暂停</button>}
        {item.status === "suspended" && <button className="button secondary" type="button" onClick={() => transition(item, "active")} disabled={!deploymentReady}>恢复</button>}
        {["active", "suspended"].includes(item.status) && <button className="button secondary" type="button" onClick={() => toggleRollback(item)} disabled={rollbackLoading || rollbackBusy}>{rollbackInstallationID === item.id ? "收起回滚" : "回滚版本"}</button>}
        {rollbackInstallationID === item.id && <span className="rollback-controls">
          {rollbackLoading ? <small>正在读取已发布版本…</small> : rollbackOptions.length ? <>
            <label><span>回滚目标版本</span><select value={rollbackVersionID} onChange={(event) => setRollbackVersionID(event.target.value)}>
              {rollbackOptions.map((version) => <option key={version.id} value={version.id}>{version.semantic_version} · {version.id}</option>)}
            </select></label>
            <button className="button secondary danger" type="button" onClick={() => rollback(item)} disabled={!rollbackVersionID || rollbackBusy}>{rollbackBusy ? "正在回滚…" : "确认回滚"}</button>
            <small>回滚只切换到已发布版本并递增 revision；随后需由平台管理员创建目标版本的 Deployment 并完成 Ready 观测。</small>
          </> : <small>没有可回滚的其他已发布版本。</small>}
        </span>}
        {["provisioning", "suspended"].includes(item.status) && !deploymentReady && <small className="form-hint">等待平台管理员创建当前版本的 Deployment 并观测为 ready 后，才能激活或恢复。</small>}
        {["active", "suspended", "draining"].includes(item.status) && <button className="button secondary danger" type="button" onClick={() => uninstall(item)}>开始卸载</button>}
      </div>;
      })}</div>
      {installations.length === 0 && <p className="form-hint">当前应用尚无 Agent Installation。</p>}
    </>}
  </section></Localized>;
}
