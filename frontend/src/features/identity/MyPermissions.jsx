import { Localized, useLanguage } from "../../components/Localization.jsx";
import { administrationKind } from "./administration-state.js";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { asItems } from "../../state.js";
import { formatTime } from "../../format.js";
import { actionName, roleName as displayRoleName, installationName, resourceName, dataScopeName, sourceName } from "../../presentation.js";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";

const active = item => item.status === "active" && (!item.starts_at || Date.parse(item.starts_at) <= Date.now()) && (!item.expires_at || Date.now() < Date.parse(item.expires_at));
const inWorkspace = (scope, user) => ["tenant_id", "department_id", "application_id"].every(key => !scope[key] || scope[key] === user[key]);
const reasonLabels = { EXPLICIT_ALLOW: "具有匹配的资源授权", EXPLICIT_DENY: "存在优先适用的拒绝规则", ROLE_REQUIRED: "缺少当前范围的岗位资格或有效成员关系", RESOURCE_GRANT_REQUIRED: "没有当前有效的资源授权", PRINCIPAL_DISABLED: "账号已停用", TENANT_MISMATCH: "资源不属于当前组织", SCOPED_ROLE: "具有当前范围的管理身份", RESOURCE_NOT_PUBLISHED: "资源尚未发布，不能正式运行", RESOURCE_UNAVAILABLE: "资源已停用或下线，不能正式运行", SELF_REVIEW_DENIED: "不能审核本人负责或参与的事项", DATA_SCOPE_MISMATCH: "该记录不在此操作的数据授权范围内" };
const diagnosticLabels = { MEMBERSHIP_INACTIVE: "成员关系已停用", MEMBERSHIP_NOT_STARTED: "成员关系尚未生效", MEMBERSHIP_EXPIRED: "成员关系已到期", ROLE_INACTIVE: "岗位已停用", ROLE_NOT_STARTED: "岗位尚未生效", ROLE_EXPIRED: "岗位已到期", GRANT_INACTIVE: "资源授权已撤销", GRANT_NOT_STARTED: "资源授权尚未生效", GRANT_EXPIRED: "资源授权已到期" };

export function MyPermissions({ user }) {
  useLanguage();
  const scopeText = useScopeName();
  const [profile, setProfile] = useState(null), [error, setError] = useState(""), [refresh, setRefresh] = useState(0);
  const [catalog, setCatalog] = useState([]), [installation, setInstallation] = useState(""), [action, setAction] = useState("run"), [decision, setDecision] = useState(null), [explainError, setExplainError] = useState(""), [busy, setBusy] = useState(false);
  const [objectID, setObjectID] = useState("");
  const explanationRequest = useRef(0);
  const clearExplanation = () => { explanationRequest.current++; setDecision(null); setExplainError(""); setBusy(false); };
  useEffect(() => {
    let current = true;
    setProfile(null); setError(""); setCatalog([]); setInstallation(""); setDecision(null); setExplainError("");
    explanationRequest.current++; setObjectID(""); setBusy(false);
    Promise.all([api.identityAccessProfile(user.username), api.myAgentCatalog()]).then(([value, agents]) => { if (current) { setProfile(value); setCatalog(asItems(agents)); } })
      .catch(cause => { if (current) setError(cause.message || "权限详情暂时无法读取，请稍后重试。"); });
    return () => { current = false; explanationRequest.current++; };
  }, [user.username, user.tenant_id, user.department_id, user.application_id, refresh]);
  const roles = asItems(profile?.role_bindings);
  const currentRoles = roles.filter(item => active(item) && inWorkspace(item.scope, user));
  const roleName = item => displayRoleName(item.role_code, asItems(profile?.role_definitions).filter(role => role.role_version === item.role_version));
  const grants = asItems(profile?.resource_grants).filter(item => active(item) && inWorkspace(item, user));
  const explain = async event => {
    event.preventDefault(); setBusy(true); setDecision(null); setExplainError("");
    const request = ++explanationRequest.current;
    try {
      const result = await api.identityExplainPermission({ action, scope: { scope_type: "agent_installation", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id, resource_id: installation }, resource_type: "agent_installation", resource_id: installation, ...(action !== "run" && objectID.trim() ? { object_id: objectID.trim() } : {}) });
      if (request === explanationRequest.current) setDecision(result);
    } catch (cause) { if (request === explanationRequest.current) setExplainError(cause.message); }
    finally { if (request === explanationRequest.current) setBusy(false); }
  };
  return <Localized><>
    <div className="page-title"><div><p className="eyebrow">身份与授权</p><h2>{administrationKind(user) ? "我的管理范围" : "我的身份与权限"}</h2><p>权限按公司工作空间、部门和 Agent 逐级限定。实际操作以平台当前权限检查为准。</p></div></div>
    {administrationKind(user) && <section className="card"><h3>此账号用于管理</h3><p>管理员不能为自己新建权限申请或增加业务权限。公司管理员负责部门归属和管理边界；部门管理员只能从公司授予的 Agent 范围内，为本部门其他用户办理使用权限。</p></section>}
    <section className="card"><div className="card-heading"><h3>当前工作空间 · {scopeText(user)}</h3><button className="button secondary" onClick={() => setRefresh(value => value + 1)}>刷新权限</button></div>
      {error && <p role="alert" className="form-error">{error}</p>}
      {!profile && !error && <p>正在读取权限详情…</p>}
      {profile && <>
        <div aria-label="当前工作空间岗位">{currentRoles.length ? currentRoles.map(item => <p key={item.id}>{roleName(item)} · 版本 {item.role_version} · {item.starts_at ? formatTime(item.starts_at) + " 生效" : "已生效"} · {item.expires_at ? formatTime(item.expires_at) + " 到期" : "长期"}</p>) : <p>当前工作空间暂无有效岗位。</p>}</div>
        <h3>当前资源授权</h3><p>当前有效授权 {grants.length} 项，其中拒绝规则 {grants.filter(item => item.effect === "deny").length} 项。岗位和资源分别办理；实际操作会优先核验拒绝规则。</p>
        <details className="technical-details"><summary>查看当前授权的资源、操作与期限</summary><div aria-label="当前工作空间资源授权">{grants.length ? grants.map(item => <article className="permission-record" key={item.id}><p>{item.effect === "deny" ? "拒绝" : "允许"} · {resourceName(item.resource_type, item.resource_id, catalog)} · {actionName(item.action)} · {dataScopeName(item.data_scope?.type)} · {item.expires_at ? formatTime(item.expires_at) + " 到期" : "长期"}</p><TechnicalDetails values={{ "授权编号": item.id, "资源编号": item.resource_id, "操作代码": item.action, "授权来源": item.source_id, "明确记录编号": item.data_scope?.ids?.length ? item.data_scope.ids : undefined }}/></article>) : <p>当前工作空间暂无有效资源授权。</p>}</div></details>
        <details className="technical-details"><summary>查看全部工作空间岗位及历史（{roles.length} 项）</summary><div aria-label="全部工作空间岗位">{roles.length ? roles.map(item => <div className="permission-record" key={item.id}>{scopeText(item.scope)} · {roleName(item)} · {active(item) ? "有效" : "当前未生效"}<TechnicalDetails values={{ "岗位绑定编号": item.id, "完整范围": item.scope, "生效时间": item.starts_at, "到期时间": item.expires_at }}/></div>) : <p>尚未配置岗位身份。</p>}</div></details>
        <details className="technical-details"><summary>全部资源授权范围（{asItems(profile.resource_grants).length} 项）</summary><div aria-label="全部资源授权范围">{asItems(profile.resource_grants).map(item => <article key={item.id} className="permission-record"><p>{scopeText(item)} · {resourceName(item.resource_type, item.resource_id, catalog)} · {actionName(item.action)} · {item.effect === "deny" ? "拒绝" : "允许"} · {dataScopeName(item.data_scope?.type)} · {active(item) ? "有效" : "已失效"}</p><TechnicalDetails values={{ "工作空间编号": { tenant_id: item.tenant_id, department_id: item.department_id, application_id: item.application_id }, "资源编号": item.resource_id, "操作代码": item.action }}/></article>)}</div></details>
        <h3>我的办理委托</h3>{!asItems(profile.delegations).length && <p>暂无授权办理委托。</p>}{asItems(profile.delegations).map(item => <article key={item.id} className="permission-record"><p>{scopeText(item.scope)} · {item.management_actions.map(actionName).join("、")} · {active(item) ? "有效" : "已失效"}</p><p>可授予岗位：{asItems(item.roles).map(code => displayRoleName(code)).join("、") || "无"}；业务操作：{asItems(item.actions).map(actionName).join("、") || "无"}；资源：{[...asItems(item.resources).map(id => resourceName("agent_installation", id, catalog)), ...asItems(item.resource_bindings).map(resource => resourceName(resource.resource_type, resource.resource_id, catalog))].join("、") || "无"}。</p><p>数据范围：{asItems(item.data_scope_types).map(dataScopeName).join("、") || "无"}；授权最长 {item.max_duration_seconds / 86400} 天；{item.allow_permanent ? "允许长期授权" : "禁止长期授权"}；委托{item.expires_at ? formatTime(item.expires_at) + " 到期" : "长期有效"}。</p><TechnicalDetails values={{ "委托编号": item.id, "范围": item.scope, "岗位代码": item.roles, "操作代码": item.actions, "资源编号": item.resources }}/></article>)}
        <form aria-label="查询本人权限解释" onSubmit={explain}><h3>查询我能否执行某项操作</h3><p>以下结果核对岗位与资源资格；访问具体事项时还会核验记录归属及审核指派。</p><fieldset disabled={busy}>
          <label>当前应用智能体<select required name="installation_id" value={installation} onChange={event => { setInstallation(event.target.value); setObjectID(""); clearExplanation(); }}><option value="">请选择</option>{catalog.map(item => <option key={item.installation_id} value={item.installation_id} title={item.installation_id}>{installationName(item)}</option>)}</select></label>
          <label>操作<select name="action" value={action} onChange={event => { setAction(event.target.value); setObjectID(""); clearExplanation(); }}><option value="run">运行</option><option value="history.read">查看历史</option><option value="history.export">导出历史</option><option value="business.review">业务审核</option><option value="business.content.read">查看审核内容</option><option value="cancel">取消运行</option></select></label>
          {action !== "run" && <label>业务事项或运行记录 ID（可选）<input name="object_id" value={objectID} maxLength={128} onChange={event => { setObjectID(event.target.value); clearExplanation(); }} /><span>填写后核验具体记录的归属与参与人；留空查询当前资源资格。</span></label>}
          <button className="button secondary" disabled={!installation} type="submit">查询权限原因</button>
        </fieldset></form>
        {explainError && <p role="alert">{explainError}</p>}{decision && <div aria-label="本人权限解释结果"><p>{decision.allowed ? "允许" : "拒绝"}：{reasonLabels[decision.reason_code] || "未满足当前操作的授权条件"}</p>
          {decision.object_id && <p>具体记录：{decision.object_id}</p>}
          <p>匹配岗位来源：{asItems(decision.matched_role_bindings ?? asItems(decision.binding_ids).map(id => roles.find(item => item.id === id)).filter(Boolean)).map(item => `${roleName(item)}（版本 ${item.role_version}，${sourceName(item.source_id)}）`).join("、") || "无"}。</p>
          {asItems(decision.matched_resource_grants).map(item => <div key={item.id}><p>{item.effect === "deny" ? "拒绝来源" : "允许来源"}：{sourceName(item.source_id)} · {dataScopeName(item.data_scope?.type)}{item.preset_code ? ` · ${displayRoleName(item.preset_code)}版本 ${item.preset_version}` : ""}</p><TechnicalDetails values={{ "授权来源": item.source_id, "岗位预设代码": item.preset_code }}/></div>)}
          {asItems(decision.diagnostic_reasons).filter(reason => diagnosticLabels[reason]).map(reason => <p key={reason}>{diagnosticLabels[reason]}</p>)}
          {decision.computed_at && <p>计算时间：{formatTime(decision.computed_at)}</p>}
		  {decision.authorization_epoch != null && <p>运行授权版本：{decision.authorization_epoch}</p>}<TechnicalDetails values={{ "智能体发布版本编号": decision.agent_version_id }}/>
        </div>}
        <h3>成员关系</h3>{asItems(profile.memberships).map(item => <p key={item.id}>{scopeText(item.scope)} · {active(item) ? "有效" : "已失效"}</p>)}
      </>}
    </section>
  </></Localized>;
}
