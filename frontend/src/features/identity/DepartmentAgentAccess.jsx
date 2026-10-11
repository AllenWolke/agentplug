import React, { useEffect, useState } from "react";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails } from "../../components/DisplayNames.jsx";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { actionName, installationName } from "../../presentation.js";
import { formatTime } from "../../format.js";
import { FreshAuthentication } from "./FreshAuthentication.jsx";
import { DAILY_AGENT_ACTIONS, replaceDepartmentAgentEntry, departmentAgentCommand, departmentAgentPendingStorageKey, departmentAgentPolicyDifferences } from "./department-agent-policy.js";

function savedPending(key) { try { return sessionStorage.getItem(key) || ""; } catch { return ""; } }
function savePending(key, value) { try { value ? sessionStorage.setItem(key, value) : sessionStorage.removeItem(key); } catch {} }

export function DepartmentAgentAccess({ user, department, onClose }) {
  useLanguage();
  const storageKey = departmentAgentPendingStorageKey(user, department.id);
  const [state, setState] = useState(null), [entries, setEntries] = useState([]), [actions, setActions] = useState([]);
  const [apps, setApps] = useState({ items: [], total: 0 }), [appPage, setAppPage] = useState(1), [app, setApp] = useState("");
  const [catalog, setCatalog] = useState([]), [cursor, setCursor] = useState(""), [next, setNext] = useState("");
  const [knownTargets, setKnownTargets] = useState({});
  const [search, setSearch] = useState(""), [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null), [acknowledged, setAcknowledged] = useState(false);
  const [pending, setPending] = useState(() => savedPending(storageKey));
  const [loading, setLoading] = useState(true), [targetsLoading, setTargetsLoading] = useState(false), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [success, setSuccess] = useState(false), [generation, setGeneration] = useState(0);
  const scope = { tenant_id: user.tenant_id, department_id: department.id };
  const frozen = busy || loading || Boolean(pending);
  useEffect(() => {
    let active = true; setLoading(true); setState(null); setPlan(null); setAcknowledged(false);
    Promise.all([api.departmentAgentPolicy(scope), api.identityPermissionActions()]).then(([policy, directory]) => {
      if (active) { setState(policy); setEntries(policy.policy.entries || []); setActions(asItems(directory).filter(action => !action.management)); }
    }).catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [user.tenant_id, department.id, generation]);
  useEffect(() => {
    let active = true; setApps({ items: [], total: 0 });
    api.applications({ ...scope, page: appPage, page_size: 20 }).then(value => { if (active) { setApps(value); if (!app) setApp(asItems(value)[0]?.id || ""); } })
      .catch(cause => { if (active) setError(cause.message); });
    return () => { active = false; };
  }, [user.tenant_id, department.id, appPage]);
  useEffect(() => {
    let active = true; setCatalog([]); setNext("");
    if (!app) return () => { active = false; };
    setTargetsLoading(true);
    api.identityInstallationTargets({ ...scope, application_id: app }, "delegation", cursor).then(value => {
      if (active) { setCatalog(asItems(value)); setNext(value.next_cursor || ""); setKnownTargets(old => ({ ...old, ...Object.fromEntries(asItems(value).map(item => [item.id, item])) })); }
    }).catch(cause => { if (active) setError(cause.message); }).finally(() => { if (active) setTargetsLoading(false); });
    return () => { active = false; };
  }, [user.tenant_id, department.id, app, cursor]);
  const changeEntry = (id, update) => { setEntries(values => replaceDepartmentAgentEntry(values, app, id, update)); setPlan(null); setAcknowledged(false); setSuccess(false); };
  const preview = async event => {
    event.preventDefault(); if (frozen) return;
    setBusy(true); setError(""); setPlan(null); setSuccess(false); setAcknowledged(false);
    try { setPlan(await api.previewDepartmentAgentChange(departmentAgentCommand({ state, tenant: user.tenant_id, department: department.id, entries, reason, key: crypto.randomUUID() }))); }
    catch (cause) { setError(cause.message); } finally { setBusy(false); }
  };
  const applyReceipt = receipt => {
    setState(value => ({ ...value, managed: true, policy: receipt.policy })); setEntries(receipt.policy.entries || []);
    setPlan(null); setSuccess(true); setPending(""); savePending(storageKey, "");
  };
  const commit = async proof => {
    const key = plan.change.idempotency_key; setError(""); setPending(key); savePending(storageKey, key);
    try { applyReceipt(await api.commitDepartmentAgentChange({ ...plan.change, step_up_token: proof.step_up_token })); }
    catch (cause) {
      if (cause.status >= 400 && cause.status < 500) {
        setPending(""); savePending(storageKey, "");
        if (cause.status === 409) setPlan(null);
      }
      setError(cause.message); throw cause;
    }
    finally { setBusy(false); }
  };
  const recover = async () => {
    setBusy(true); setError("");
    try { applyReceipt(await api.departmentAgentChangeReceipt(pending)); }
    catch (cause) { setError(cause.status === 404 ? "尚未查询到本次结果，请稍后再次查询。查询不会重复提交。" : cause.message); }
    finally { setBusy(false); }
  };
  const visible = new Map(catalog.filter(item => ["active", "provisioning"].includes(item.status)).map(item => [item.id, item]));
  for (const entry of entries.filter(item => item.application_id === app)) if (!visible.has(entry.installation_id)) visible.set(entry.installation_id, { id: entry.installation_id });
  const values = [...visible.values()].filter(item => installationName(item).toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  const changed = !state?.managed || departmentAgentPolicyDifferences(state.policy, { entries }).length > 0;
  const changeVisible = enabled => {
    setEntries(old => values.reduce((result, item) => replaceDepartmentAgentEntry(result, app, item.id, current => enabled ? current || { actions: [...DAILY_AGENT_ACTIONS] } : null), old));
    setPlan(null); setAcknowledged(false); setSuccess(false);
  };
  return <Localized><section className="card department-agent-access" aria-label="部门可用 Agent 配置">
    <div className="card-heading"><h3><span>部门可用 Agent · </span><span data-i18n-preserve>{department.name}</span></h3><div className="pagination-controls"><button className="button secondary" disabled={busy || Boolean(pending)} title="刷新将取消未提交的编辑" onClick={() => { setError(""); setSuccess(false); setGeneration(value => value + 1); }}>刷新配置</button><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div></div>
    <p>先由公司开通部门可用的 Agent，再由部门管理员分配给成员。开通部门范围不会自动给成员授权。</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    {success && <p className="success-banner" role="status">部门可用 Agent 已更新。成员仍需单独获得使用权限。</p>}
    {pending && <div className="empty-state" role="status"><h4>正在确认提交结果</h4><p>使用原请求编号查询，不会重新提交授权变更。重新打开此部门也可继续查询。</p><TechnicalDetails values={{ "请求编号": pending }}/><button className="button secondary" disabled={busy} onClick={recover}>查询本次结果</button></div>}
    {loading ? <p>正在读取部门授权配置…</p> : state && !state.can_manage ? <p>只有公司管理员可调整部门可用 Agent。</p> : state && <>
      {!state.managed && <p className="form-hint">此部门仍使用旧授权规则。首次保存将启用部门范围限制；旧权限模式的账号须先完成权限迁移。</p>}
      <form onSubmit={preview}>
        <fieldset disabled={frozen} className="form"><legend>选择部门可用 Agent</legend>
          <label>Agent 所在应用范围<select value={app} onChange={event => { setApp(event.target.value); setCursor(""); setSearch(""); }}><option value="">请选择</option>{asItems(apps).map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <div className="pagination-controls"><button className="button secondary" type="button" disabled={appPage === 1} onClick={() => { setAppPage(page => page - 1); setApp(""); setCursor(""); }}>上一页应用</button><button className="button secondary" type="button" disabled={appPage * 20 >= apps.total} onClick={() => { setAppPage(page => page + 1); setApp(""); setCursor(""); }}>下一页应用</button></div>
          <label>查找当前列表中的 Agent<input value={search} onChange={event => setSearch(event.target.value)}/></label>
          <p className="form-hint">勾选默认开通日常使用，可展开调整操作和有效期。其他应用中已配置的 Agent 会保留。</p>
          <div className="pagination-controls"><button className="button secondary" type="button" disabled={targetsLoading || !values.length} onClick={() => changeVisible(true)}>开通当前筛选结果</button><button className="button secondary" type="button" disabled={targetsLoading || !values.length} onClick={() => changeVisible(false)}>移除当前筛选结果</button></div>
          {targetsLoading ? <p>正在读取 Agent…</p> : !app ? <p>请先选择应用范围。</p> : !values.length ? <p>当前列表没有可选 Agent。</p> : <div className="record-list">{values.map((item, index) => {
            const entry = entries.find(value => value.application_id === app && value.installation_id === item.id);
            return <div key={item.id}><div className="department-agent-option">
              <label className="checkbox-row"><input type="checkbox" checked={Boolean(entry)} onChange={event => changeEntry(item.id, () => event.target.checked ? { actions: [...DAILY_AGENT_ACTIONS] } : null)}/><b>{item.agent_id || item.display_name ? installationName(item) : <><span>已配置 Agent </span>{index + 1}</>}</b></label>
              {entry && <details className="technical-details"><summary>调整操作与有效期</summary>
                <div className="permission-check-grid">{actions.map(action => <label key={action.code} className="checkbox-row"><input type="checkbox" checked={entry.actions.includes(action.code)} onChange={event => changeEntry(item.id, current => ({ ...current, actions: event.target.checked ? [...current.actions, action.code] : current.actions.filter(value => value !== action.code) }))}/>{actionName(action.code)}{action.sensitive && <span>（敏感操作）</span>}</label>)}</div>
                <label>开始时间（留空立即生效）<input type="datetime-local" value={localDateTime(entry.starts_at)} onChange={event => changeEntry(item.id, current => ({ ...current, starts_at: event.target.value ? new Date(event.target.value).toISOString() : undefined }))}/></label>
                <label>到期时间（留空长期）<input type="datetime-local" value={localDateTime(entry.expires_at)} onChange={event => changeEntry(item.id, current => ({ ...current, expires_at: event.target.value ? new Date(event.target.value).toISOString() : undefined }))}/></label>
                <p>分享、导出及审核等敏感操作，仍须由具备资格的管理员另行授权。</p>
                <TechnicalDetails values={{ "安装实例": item.id, "应用编号": app }}/>
              </details>}
              {!entry && <TechnicalDetails values={{ "安装实例": item.id, "应用编号": app }}/>}
            </div></div>;
          })}</div>}
          <div className="pagination-controls"><button className="button secondary" type="button" disabled={!cursor || targetsLoading} onClick={() => setCursor("")}>返回第一页 Agent</button><button className="button secondary" type="button" disabled={!next || targetsLoading} onClick={() => setCursor(next)}>下一页 Agent</button></div>
          <p>本部门共选入 {entries.length} 个 Agent</p>
          <label>调整原因<textarea required maxLength={1000} value={reason} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
          <button className="button primary" disabled={busy || !reason.trim() || !changed}>预览调整影响</button>
        </fieldset>
      </form>
      {plan && !pending && <section className="plan-preview" aria-label="部门授权影响预览"><h4>核对调整影响</h4><dl>
        <dt>调整后部门可用 Agent</dt><dd>{plan.after.entries.length}</dd>
        <dt>可能受限的账号</dt><dd>{plan.impact.potential_restricted_subjects}</dd>
        <dt>可能受限的授权记录</dt><dd>{plan.impact.potential_restricted_grants}</dd>
        <dt>须迁移旧权限的账号</dt><dd>{plan.impact.legacy_subjects}</dd>
        <dt>预览有效至</dt><dd>{formatTime(plan.expires_at)}</dd>
      </dl><div className="record-list">{departmentAgentPolicyDifferences(plan.before, plan.after).map((difference, index) => {
        const entry = difference.after || difference.before;
        const daily = difference.after?.actions.length === DAILY_AGENT_ACTIONS.length && DAILY_AGENT_ACTIONS.every(action => difference.after.actions.includes(action));
        return <div key={JSON.stringify([entry.application_id, entry.installation_id])}><div><b>{knownTargets[entry.installation_id] ? installationName(knownTargets[entry.installation_id]) : <><span>已配置 Agent </span>{index + 1}</>}</b><p>{!difference.after ? "收回此 Agent 的部门使用范围" : daily ? "日常使用（运行、会话与所需资源）" : <><span>自定义操作数量：</span>{difference.after.actions.length}</>}</p><details className="technical-details"><summary>查看本项调整详情</summary>{difference.before && <p><span>调整前：</span>{difference.before.actions.map(actionName).join(" · ")}</p>}{difference.after && <p><span>调整后：</span>{difference.after.actions.map(actionName).join(" · ")}</p>}<p><span>开始时间：</span>{entry.starts_at ? formatTime(entry.starts_at) : "立即生效"}<span>；到期时间：</span>{entry.expires_at ? formatTime(entry.expires_at) : "长期"}</p><TechnicalDetails values={{ "安装实例": entry.installation_id, "应用编号": entry.application_id }}/></details></div><span>{difference.kind === "added" ? "新增开通" : difference.kind === "removed" ? "收回范围" : "调整范围"}</span></div>;
      })}</div><p>范围收回后，后续操作会按新权限校验。重新开通不会自动恢复部门管理员发出的旧授权；取消已有运行的权限会保留。</p><p>这些数字表示可能受限的授权，不代表正在运行的任务数，也不会撤回已经完成的操作。</p>
        {!state.managed && <label className="checkbox-row"><input type="checkbox" checked={acknowledged} disabled={busy} onChange={event => setAcknowledged(event.target.checked)}/>我已核对旧账号迁移和权限限制的影响</label>}
        {(state.managed || acknowledged) && <FreshAuthentication key={plan.digest} action={plan.step_up_action} requestDigest={plan.digest} onProof={commit} onBusy={setBusy}/>}
      </section>}
    </>}
  </section></Localized>;
}

function localDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
