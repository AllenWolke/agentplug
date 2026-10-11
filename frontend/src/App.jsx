import { Localized, useLanguage } from "./components/Localization.jsx";
import React, { createContext, lazy, Suspense, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { MyPermissions } from "./features/identity/MyPermissions.jsx";
import { api } from "./api.js";
import {
  ROLE_LABELS, canAudit, canReview, canUseEvaluationWorkspace, defaultLanding, isAppAdmin,
  isIntegrationAdmin, isPlatformAdmin, isSystemAdmin, canManageUsers, canManageAccessRequests, canReviewConversationDeletion, canManagePolicyAssets, canManageCatalog, canConfigureModels, canDevelopAgents, rolesOf, visibleApplications
} from "./config.js";
import { asItems, createRecentStore, lastDaysRange } from "./state.js";
import { formatStatus, formatTime, shortId, statusTone } from "./format.js";
import { AgentWorkspace } from "./features/agent-workspace/AgentWorkspace.jsx";
import PolicyAssetAdmin from "./features/policy-asset/PolicyAssetAdmin.jsx";
import SkillAdmin, { canManageSkills } from "./features/skills/SkillAdmin.jsx";
import { ApplicationAgentInstallations } from "./features/agent-catalog/ApplicationAgentInstallations.jsx";
import { MachineCredentialAdmin } from "./features/identity/MachineCredentialAdmin.jsx";
import { DepartmentAdmin } from "./features/identity/DepartmentAdmin.jsx";
import { EnrollmentPermissionApproval } from "./features/identity/EnrollmentPermissionApproval.jsx";
import { EnrollmentRejection } from "./features/identity/EnrollmentRejection.jsx";
import { administrationKind, businessAgentChoices, canRequestOwnPermissions, departmentWorkspace, preferredWorkspaceIDs, workspaceChoices } from "./features/identity/administration-state.js";
import { projectSessionIdentity, workspaceDisplayIdentity } from "./features/identity/workspace-state.js";
import { agentPresentation, agentWorkspacePath } from "./features/agent-workspace/catalog-presentation.js";
import { auditMetadataQuery } from "./features/identity/audit-query.js";
import { AuditEventContent } from "./features/identity/AuditEventContent.jsx";
import { CredentialSettings } from "./features/identity/CredentialSettings.jsx";
import { loadAgentAccessReview, loadEnrollmentReview } from "./features/identity/access-admin-loader.js";
import { applicationCreateCommand } from "./features/identity/application-command.js";
import { ConversationDeletionReview } from "./features/agent-workspace/ConversationDeletionReview.jsx";
import { PersonalInbox } from "./features/notification/PersonalInbox.jsx";
import { ConversationHistory } from "./features/agent-workspace/ConversationHistory.jsx";
import { DisplayNamesContext, TechnicalDetails } from "./components/DisplayNames.jsx";
import { LanguageSwitcher } from "./components/Localization.jsx";
import { translateUI } from "./localization.js";
import { scopeName } from "./presentation.js";
import { UserGuide } from "./features/help/UserGuide.jsx";

const AuthContext = createContext(null);
const PublishedAgentContext = createContext({ items: [], loading: true, initialized: false });
const recent = createRecentStore();
const ModelGovernance = lazy(() => import("./features/model-governance/ModelGovernance.jsx"));
const AgentFactory = lazy(() => import("./features/agent-factory/AgentFactory.jsx").then(module => ({ default: module.AgentFactory })));
const EvaluationWorkspace = lazy(() => import("./features/evaluation-workspace/EvaluationWorkspace.jsx").then(module => ({ default: module.EvaluationWorkspace })));
const AdapterMapping = lazy(() => import("./features/adapter-mapping/AdapterMapping.jsx").then(module => ({ default: module.AdapterMapping })));
const AgentCatalog = lazy(() => import("./features/agent-catalog/AgentCatalog.jsx").then(module => ({ default: module.AgentCatalog })));
const PrincipalAdmin = lazy(() => import("./features/identity/PrincipalAdmin.jsx").then(module => ({ default: module.PrincipalAdmin })));
const PermissionRequests = lazy(() => import("./features/identity/PermissionRequests.jsx").then(module => ({ default: module.PermissionRequests })));

function AuthProvider({ children }) {
  useLanguage();
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(false);
  const [switchingWorkspace, setSwitchingWorkspace] = useState(false);
  const [workspaces, setWorkspaces] = useState({ owner: "", items: [] });
  const refresh = useCallback(async () => {
    try { const identity = await api.me(); const projection = await api.identityPermissions(); setUser(projectSessionIdentity(identity, projection)); } catch { setUser(null); }
    finally { setReady(true); }
  }, []);
  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const channel = typeof BroadcastChannel === "function" ? new BroadcastChannel("agentplug-workspace") : null;
    if (channel) channel.onmessage = event => { if (event.data === "changed") { recent.clear(); setSwitchingWorkspace(true); refresh().finally(() => setSwitchingWorkspace(false)); } };
    return () => channel?.close();
  }, [refresh]);
  const switchWorkspace = async target => {
    const identity = await api.switchWorkspace(target);
    // Clear the previous workspace immediately, including caches and drafts.
    recent.clear(); setSwitchingWorkspace(true);
    try {
      setUser({ ...identity, policy_mode: "v2", capabilities: [], role_bindings: [] });
      const projection = await api.identityPermissions();
      setUser(projectSessionIdentity(identity, projection));
    } finally {
      setSwitchingWorkspace(false);
      if (typeof BroadcastChannel === "function") { const channel = new BroadcastChannel("agentplug-workspace"); channel.postMessage("changed"); channel.close(); }
    }
  };
  const login = async (username, password) => { const identity = await api.login(username, password); const projection = await api.identityPermissions(); const next = projectSessionIdentity(identity, projection); setUser(next); return next; };
  const logout = async () => {
    let logoutURL;
    try {
      const result = await api.logout();
      logoutURL = result?.logout_url;
    } finally { recent.clear(); setUser(null); }
    if (logoutURL === "/oauth2/sign_out") {
      window.location.assign(logoutURL);
      return true;
    }
    return false;
  };
  const updateWorkspaceLabels = useCallback((items, expected) => {
    setWorkspaces({ owner: expected.username, items });
    setUser(current => current && ["username", "tenant_id", "department_id", "application_id"].every(key => current[key] === expected[key]) ? workspaceDisplayIdentity(current, items) : current);
  }, []);
  const updatePermissionProjection = useCallback((projection, expected) => {
    setUser(current => {
      if (!current || ["username", "tenant_id", "department_id", "application_id"].some(key => current[key] !== expected[key])) return current;
      return projectSessionIdentity(current, projection);
    });
  }, []);
  return <Localized><AuthContext.Provider value={{ user, ready, login, logout, switchWorkspace, switchingWorkspace, updatePermissionProjection, updateWorkspaceLabels }}><DisplayNamesContext.Provider value={{ user: user || {}, workspaces: user?.username === workspaces.owner ? workspaces.items : [] }}>{children}</DisplayNamesContext.Provider></AuthContext.Provider></Localized>;
}

function useAuth() { return useContext(AuthContext); }

function useRemote(loader, dependencies = []) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const request = useRef(0);
  const load = useCallback(async (silent = false) => {
    const generation = ++request.current;
    if (!silent) setState((current) => ({ ...current, loading: true, error: null }));
    try { const data = await loader(); if (generation === request.current) setState({ loading: false, data, error: null }); }
    catch (error) { if (generation === request.current) setState((current) => ({ loading: false, data: silent && ![401, 403].includes(error.status) ? current.data : null, error })); }
  }, dependencies);
  const reload = useCallback(() => load(false), [load]);
  const refresh = useCallback(() => load(true), [load]);
  useEffect(() => { reload(); return () => { request.current++; }; }, [reload]);
  return { ...state, reload, refresh };
}

function Loading({ label = "正在读取平台数据" }) {
  useLanguage(); return <Localized><div className="state-panel"><span className="spinner"/><p>{label}</p></div></Localized>; }
function ErrorPanel({ error, retry }) {
  useLanguage(); return <Localized><div className="state-panel error"><b>请求未完成</b><p>{error?.message || "未知错误"}</p>{error?.traceId && <code>{error.traceId}</code>}{retry && <button className="button secondary" onClick={retry}>重新加载</button>}</div></Localized>; }
function Empty({ title, description }) {
  useLanguage(); return <Localized><div className="empty"><span>◇</span><b>{title}</b><p>{description}</p></div></Localized>; }
function Badge({ value }) {
  useLanguage(); return <Localized><span className={`badge ${statusTone(value)}`}><i/>{formatStatus(value)}</span></Localized>; }
function Metric({ label, value, hint, tone = "blue" }) {
  useLanguage(); return <Localized><article className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong><small>{hint}</small></article></Localized>; }
function PageTitle({ eyebrow, title, description, actions }) {
  useLanguage(); return <Localized><div className="page-title"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2><p>{description}</p></div>{actions && <div className="title-actions">{actions}</div>}</div></Localized>; }

function LoginPage() {
  useLanguage();
  const { login } = useAuth();
  const navigate = useNavigate();
  const [values, setValues] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault(); setBusy(true); setError("");
    try { const user = await login(values.username, values.password); navigate(defaultLanding(user), { replace: true }); }
    catch (reason) { setError(reason.message); }
    finally { setBusy(false); }
  };
  return <Localized><main className="login-page">
    <section className="login-story">
      <Link className="brand large" to="/"><span className="brand-mark">A</span><span><b>AgentPlug</b><small>企业级智能体中台</small></span></Link>
      <div className="login-copy"><p className="eyebrow">使用、接入与治理</p><h1>让每个部门安全地使用、发布和治理自己的智能体。</h1><p>在统一工作空间中使用业务 Agent，管理授权、版本、运行与审计。</p></div>
      <div className="login-proof"><span>身份认证</span><span>四级隔离</span><span>版本治理</span><span>全链路审计</span></div>
    </section>
    <section className="login-panel">
      <Link className="brand login-mobile-brand" to="/"><span className="brand-mark">A</span><span><b>AgentPlug</b><small>智能体中台</small></span></Link>
      <LanguageSwitcher/>
      <form onSubmit={submit} className="login-form" id="login-form">
        <div><p className="eyebrow">账号登录</p><h2>登录智能体中台</h2><p>身份验证后只展示账号有权访问的应用与管理空间。</p></div>
        <label><span>登录账号</span><input name="username" autoComplete="username" value={values.username} onChange={(e) => setValues({ ...values, username: e.target.value })} required/></label>
        <label><span>密码</span><input name="password" type="password" autoComplete="current-password" value={values.password} onChange={(e) => setValues({ ...values, password: e.target.value })} required/></label>
        {error && <div className="form-error">{error}</div>}
        <button className="button primary wide" disabled={busy}>{busy ? "正在验证…" : "验证身份并进入"}</button>
		<Link className="text-button register-link" to="/register">没有账号？申请注册</Link>
      </form>
    </section>
  </main></Localized>;
}

function RegisterPage() {
  useLanguage();
  const navigate = useNavigate();
  const [busy,setBusy]=useState(false); const [error,setError]=useState(""); const [result,setResult]=useState(null); const [verified,setVerified]=useState(null);
  const availableAgents=useRemote(()=>api.registrationAgentCatalog(),[]);
  const submit=async(event)=>{event.preventDefault();setBusy(true);setError("");try{const values=Object.fromEntries(new FormData(event.currentTarget));values.requested_agent_ids=Array.from(event.currentTarget.querySelectorAll('input[name="requested_agent_ids"]:checked')).map((item)=>item.value);setResult(await api.register(values));}catch(reason){setError(reason.message)}finally{setBusy(false)}};
  const verify=async(event)=>{event.preventDefault();setBusy(true);setError("");try{setVerified(await api.verifyRegistration(result.registration_id,result.status_token,new FormData(event.currentTarget).get("code")));}catch(reason){setError(reason.message)}finally{setBusy(false)}};
  if(verified)return <Localized><main className="standalone-page"><section className="card registration-result"><LanguageSwitcher/><Empty title="注册申请已提交" description={`申请编号：${verified.registration_id}。联系方式已验证，管理员审批激活后即可登录；Agent 使用权限需另行办理。`}/><button className="button primary" onClick={()=>navigate('/login')}>返回登录</button></section></main></Localized>;
  if(result)return <Localized><main className="standalone-page"><section className="card registration-result"><LanguageSwitcher/><h2>验证联系方式</h2><p>验证码已发送至企业验证渠道。开发演示模式验证码：<b>{result.verification_code || "请查看企业验证渠道"}</b></p><form className="form" onSubmit={verify}><label><span>六位验证码</span><input name="code" inputMode="numeric" pattern="[0-9]{6}" required/></label>{error&&<div className="form-error">{error}</div>}<button className="button primary" disabled={busy}>{busy?"验证中…":"验证并提交审批"}</button></form></section></main></Localized>;
  return <Localized><main className="standalone-page"><section className="card registration-card"><LanguageSwitcher/><div className="card-heading"><div><p className="eyebrow">注册申请</p><h2>申请注册智能体中台</h2></div><Link to="/login">返回登录</Link></div><form className="form" onSubmit={submit}><label><span>登录账号</span><input name="username" placeholder="例如：allen.user" minLength="3" required/></label><label><span>显示姓名</span><input name="display_name" minLength="2" required/></label><label><span>企业邮箱</span><input name="contact" type="email" required/></label><label><span>密码（至少 10 位）</span><input name="password" type="password" minLength="10" autoComplete="new-password" required/></label><label><span>组织邀请码</span><input name="invite_code" placeholder="由组织管理员提供" required/></label><label><span>使用理由</span><textarea name="reason" minLength="10" maxLength="500" required/></label><fieldset><legend>期望使用的 Agent（最终由管理员决定）</legend>{availableAgents.loading?<small>正在读取已上线 Agent…</small>:asItems(availableAgents.data).map((agent)=><label className="checkbox-row" key={agent.agent_id}><input type="checkbox" name="requested_agent_ids" value={agent.agent_id}/><span>{agent.name} · {agent.semantic_version}</span></label>)}</fieldset>{error&&<div className="form-error">{error}</div>}<button className="button primary wide" disabled={busy}>{busy?"正在提交…":"提交注册申请"}</button></form></section></main></Localized>;
}

const navGroups = (user, publishedAgents = []) => {
  const administrator = administrationKind(user);
  const businessAgents = businessAgentChoices(user, publishedAgents);
  const apps = administrator && !businessAgents.length ? [] : visibleApplications(user);
  const groups = [{ label: "工作空间", items: [{ to: "/workspace", label: "中台首页", icon: "⌂" }, ...apps.map((app) => ({ to: app.path, label: app.name, icon: "合" }))] }];
  groups[0].items.push({ to: "/workspace/notifications", label: "我的通知", icon: "信" });
  if (!administrator || businessAgents.length) groups[0].items.push({ to: "/workspace/history", label: "我的运行历史", icon: "申" });
  groups[0].items.push({ to: "/help", label: "开始使用与帮助", icon: "权" });
  if (businessAgents.length) groups.push({ label: "业务 Agent", agents: businessAgents, items: [] });
  const admin = [];
  if (user.policy_mode === "v2") groups[0].items.push({ to: "/workspace/my-permissions", label: administrator ? "我的管理范围" : "我的身份与权限", icon: "权" });
  if (canRequestOwnPermissions(user)) groups[0].items.push({ to: "/workspace/permission-requests", label: "我的权限申请", icon: "申" });
  if (user.policy_mode === "v2" && canManageAccessRequests(user)) admin.push({ to: "/admin/permission-requests", label: "角色与资源审批", icon: "授" });
  if (isSystemAdmin(user)) admin.push({ to: "/system/operations", label: "系统运维", icon: "S" });
  if (isPlatformAdmin(user)) admin.push({ to: "/platform/overview", label: "平台管理", icon: "P" });
  if (canConfigureModels(user)) admin.push({ to: "/platform/model-governance", label: "模型治理", icon: "M" });
  if (canManageCatalog(user)) admin.push({ to: "/platform/agent-catalog", label: "Agent 目录与安装", icon: "V" });
  if (isIntegrationAdmin(user)) admin.push({ to: "/platform/machine-credentials", label: "机器身份凭证", icon: "K" });
  if (canManageUsers(user)) admin.push({ to: "/platform/identity-principals", label: "用户主体管理", icon: "I" });
  if (["platform", "company"].includes(administrationKind(user)) && user.capabilities?.includes("organization.manage")) admin.push({ to: "/platform/departments", label: "部门管理", icon: "D" });
  if (canDevelopAgents(user)) admin.push({ to: "/platform/agent-factory", label: "Agent 工厂", icon: "F" });
  if (canUseEvaluationWorkspace(user)) admin.push({ to: "/platform/evaluations", label: "评测工作台", icon: "E" });
  if (canDevelopAgents(user)) admin.push({ to: "/platform/adapter-mappings", label: "Adapter 映射", icon: "D" });
  if (isAppAdmin(user)) admin.push({ to: "/admin/application", label: "应用与 Agent", icon: "A" });
  if (canManagePolicyAssets(user)) admin.push({ to: "/admin/policy-assets", label: "策略资产", icon: "C" });
  if (canManageSkills(user)) admin.push({ to: "/admin/skills", label: "Skill 管理", icon: "技" });
  if (canManageAccessRequests(user)) admin.push({ to: "/admin/user-access", label: "用户与 Agent 授权", icon: "U" });
  if (canReviewConversationDeletion(user)) admin.push({ to: "/admin/conversation-governance", label: "会话治理", icon: "H" });
  if (isIntegrationAdmin(user)) admin.push({ to: "/admin/integrations", label: "外部系统接入", icon: "↗" });
  if (canAudit(user)) admin.push({ to: "/audit", label: "审计查询", icon: "◎" });
  if (admin.length) groups.push({ label: "管理空间", items: admin });
  return groups;
};

function AgentNavigationSelect({ agents }) {
  useLanguage();
  const navigate = useNavigate();
  const location = useLocation();
  const current = agents.find((item) => location.pathname === agentWorkspacePath(item));
  return <Localized><label className="sidebar-agent-picker"><span>已上线 Agent（{agents.length}）</span><select name="sidebar_agent_view" value={current?.agent_id || ""} onChange={(event) => { const item = agents.find((agent) => agent.agent_id === event.target.value); if (item) navigate(agentWorkspacePath(item)); }} disabled={!agents.length}><option value="">{agents.length ? "选择 Agent" : "暂无已上线 Agent"}</option>{agents.map((item) => <option key={item.agent_id} value={item.agent_id}>{item.access_status === "granted" ? "可用" : "需授权"} · {agentPresentation(item).name}</option>)}</select></label></Localized>;
}

function AppShell() {
  useLanguage();
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const apps = visibleApplications(user);
  const agentCatalog = useRemote(async () => asItems(await api.myAgentCatalog()), [user.tenant_id, user.department_id, user.application_id]);
  const publishedAgents = agentCatalog.data || [];
  useEffect(() => { setNavigationOpen(false); }, [location.pathname]);
  useEffect(() => { const close = event => { if (event.key === "Escape") setNavigationOpen(false); }; window.addEventListener("keydown", close); return () => window.removeEventListener("keydown", close); }, []);
  useEffect(() => {
    // Catalog polling must be silent. A foreground reload marks the catalog as
    // loading, which makes AgentGuard unmount the active Agent page and loses
    // its selected conversation and draft input every polling interval.
    const refresh = () => agentCatalog.refresh();
    const timer = setInterval(refresh, 15000);
    window.addEventListener("focus", refresh);
    window.addEventListener("agent-catalog-changed", refresh);
    return () => { clearInterval(timer); window.removeEventListener("focus", refresh); window.removeEventListener("agent-catalog-changed", refresh); };
  }, [agentCatalog.refresh]);
  return <Localized><PublishedAgentContext.Provider value={{ items: publishedAgents, loading: agentCatalog.loading, initialized: agentCatalog.data !== null, error: agentCatalog.error, reload: agentCatalog.reload }}><div className={`shell${navigationOpen ? " navigation-open" : ""}`}>
    <button className="navigation-backdrop" aria-label="关闭导航" onClick={() => setNavigationOpen(false)}/>
    <aside className="sidebar" id="console-navigation">
      <Link className="brand" to="/workspace"><span className="brand-mark">A</span><span><b>AgentPlug</b><small>智能体中台</small></span></Link>
      <div className="scope-card"><span>公司工作空间</span><b>{user.workspace_name || "当前公司"}</b><small>{administrationKind(user) ? "同一公司内可管理多个部门" : "所属公司固定，按部门使用 Agent"}</small>{user.policy_mode === "v2" && <WorkspaceSelector/>}</div>
      <nav aria-label="主导航">{navGroups(user, publishedAgents).map((group) => <section key={group.label}><p>{group.label}</p>{group.agents && <AgentNavigationSelect agents={group.agents}/>} {group.items.map((item) => <NavLink end key={item.to} to={item.to}><i aria-hidden="true"><NavigationIcon name={item.icon}/></i>{item.label}</NavLink>)}</section>)}</nav>
      <div className="sidebar-status"><span>AgentPlug 控制台</span><small>开源智能体平台</small></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="topbar-identity"><button type="button" className="navigation-toggle" aria-label={navigationOpen ? "关闭主导航" : "打开主导航"} aria-expanded={navigationOpen} aria-controls="console-navigation" onClick={() => setNavigationOpen(value => !value)}><NavigationIcon name="menu"/></button><div><p className="eyebrow">{user.workspace_name || "公司工作空间"} · {user.department_name || "当前部门"}</p><b data-i18n-preserve>{user.display_name || user.username}</b></div></div><div className="user-menu"><LanguageSwitcher/><div className="role-pills">{rolesOf(user).slice(0, 2).map((role) => <span key={role}>{ROLE_LABELS[role] || role}</span>)}</div><Link className="text-button" to="/account/security">安全设置</Link><button className="logout-button" title="退出登录" aria-label="退出登录" onClick={async () => { try { if (!(await logout())) navigate("/login"); } catch { setLogoutError("退出请求未完成，请重试。"); } }}><NavigationIcon name="logout"/><span>退出</span></button></div></header>
      <main className="page" id="main-content">{logoutError && <p className="form-error" role="alert">{logoutError}</p>}<Suspense fallback={<Loading label="正在加载工作空间"/>}><RoutesView/></Suspense></main>
    </div>
  </div></PublishedAgentContext.Provider></Localized>;
}

function WorkspaceSelector() {
  useLanguage();
  const { user, switchWorkspace, updateWorkspaceLabels } = useAuth();
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [preferredApplications, setPreferredApplications] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { let active = true; setError(""); api.identityWorkspaces().then(value => { if (active) { const items = workspaceChoices(user, value); setItems(items); setPreferredApplications(preferredWorkspaceIDs(user, value)); updateWorkspaceLabels([...items, ...(value.application_workspaces || [])], user); } }).catch(cause => { if (active) setError(cause.message); }); return () => { active = false; }; }, [user.username, user.tenant_id, user.department_id, user.application_id, updateWorkspaceLabels]);
  const chooseTarget = async target => {
    if (!target) return;
    setBusy(true); setError("");
    try { await switchWorkspace({ tenant_id: target.tenant_id, department_id: target.department_id, application_id: target.application_id }); navigate("/workspace", { replace: true }); }
    catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const departments = [...new Map(items.map(item => [item.department_id, item])).values()];
  const currentAllowed = items.some(item => item.application_id === user.application_id);
  const chooseDepartment = departmentID => {
    chooseTarget(departmentWorkspace(items, departmentID, user.application_id, preferredApplications));
  };
  const applicationGroups = items.filter(item => item.department_id === user.department_id || !currentAllowed);
  const applicationSelector = <label className="workspace-selector"><span>同部门内的接入范围</span><select aria-label="切换 Agent 接入范围" value={currentAllowed ? user.application_id : ""} disabled={busy || !items.length} onChange={event => chooseTarget(items.find(item => item.application_id === event.target.value))}><option value="" disabled>请选择接入范围</option>{applicationGroups.map(item => <option key={item.application_id} value={item.application_id}>{item.application_name}</option>)}</select></label>;
  return <Localized><><label className="workspace-selector"><span>{busy ? "正在切换…" : administrationKind(user) ? "管理部门" : "所在部门"}</span><select aria-label="切换部门" value={currentAllowed ? user.department_id : ""} disabled={busy || !items.length} onChange={event => chooseDepartment(event.target.value)}><option value="" disabled>{items.length ? "请选择部门" : administrationKind(user) ? "暂无已委托的管理范围" : "暂无可进入的部门"}</option>{departments.map(item => <option key={item.department_id} value={item.department_id}>{item.department_name}</option>)}</select></label><details className="technical-details"><summary>高级接入配置</summary><p className="form-hint">同部门内的技术接入范围，不是独立公司或部门。</p>{applicationSelector}</details>{error && <p role="alert">{error}</p>}</></Localized>;
}

function Guard({ when, children }) {
  useLanguage(); return when ? children : <Localized><Navigate to="/forbidden" replace/></Localized>; }

function AgentGuard({ agentID, children }) {
  useLanguage();
  const catalog = useContext(PublishedAgentContext);
  // Only gate the first load. Subsequent catalog refreshes must not unmount a
  // page that owns in-progress UI state such as the selected session or draft.
  if (catalog.loading && !catalog.initialized) return <Localized><Loading label="正在校验 Agent 使用权限"/></Localized>;
  if (catalog.error) return <Localized><ErrorPanel error={catalog.error} retry={catalog.reload}/></Localized>;
  const agent = catalog.items.find((item) => item.agent_id === agentID);
  return agent?.access_status === "granted" ? children : <Localized><AgentAccessRequired agentID={agentID}/></Localized>;
}

function AgentAccessRequired({ agentID = "" }) {
  useLanguage();
  const location = useLocation();
  const { user } = useAuth();
  const resolved = agentID || new URLSearchParams(location.search).get("agent_id") || "unknown";
  const catalog = useContext(PublishedAgentContext);
  const installation = catalog.items.find((item) => item.agent_id === resolved);
  const [notice,setNotice]=useState("");const [error,setError]=useState("");
  const requestAccess=async(event)=>{event.preventDefault();setError("");if(!installation?.installation_id){setError("当前应用目录中未找到可申请的 Agent 安装实例，请刷新目录或联系管理员。");return}try{await api.createIdentityAgentAccessRequest({agent_instance_id:installation.installation_id,actions:["discover","run","history.read","history.continue","history.revise","history.regenerate","history.share","history.export","history.delete.request","cancel"],reason:new FormData(event.currentTarget).get("reason")});setNotice("权限申请已提交，请等待本应用管理员审批。") }catch(reason){setError(reason.message)}};
  return <Localized><><PageTitle eyebrow="使用权限" title="暂不可使用该 Agent" description="Agent 已上线，但当前用户尚未获得相应操作权限。"/><section className="card"><Empty title="您暂无权限使用该agent，需向管理员申请权限" description={installation ? agentPresentation(installation).name : "请先核对当前应用，再申请对应助手的使用权限。"}/>{notice&&<div className="success-banner">{notice}</div>}{error&&<div className="form-error">{error}</div>}{catalog.loading&&!catalog.initialized?<Loading label="正在读取应用 Agent 目录"/>:user.policy_mode === "v2" ? <Link className="button primary" to="/workspace/permission-requests">申请岗位与助手使用权限</Link> : <form className="inline-form" onSubmit={requestAccess}><input name="reason" minLength="10" placeholder="说明申请用途（至少 10 字）" required/><button className="button primary" disabled={!installation?.installation_id}>申请权限</button></form>}</section></></Localized>;
}

function RoutesView() {
  useLanguage();
  const { user, logout, updatePermissionProjection } = useAuth();
  const apps = visibleApplications(user);
  return <Localized><Routes>
    <Route path="/help" element={<UserGuide user={user}/>}/>
    <Route path="/account/security" element={<CredentialSettings user={user} logout={logout}/>}/>
    <Route path="/workspace" element={<WorkspaceHome/>}/>
    <Route path="/workspace/application" element={<ApplicationWorkspace/>}/>
    <Route path="/workspace/notifications" element={<PersonalInbox user={user}/>}/>
    <Route path="/workspace/history" element={<ConversationHistory user={user}/>}/>
    <Route path="/workspace/agent/:agentId" element={<AgentWorkspaceRoute/>}/>
    <Route path="/system/operations" element={<Guard when={isSystemAdmin(user)}><SystemOperations/></Guard>}/>
    <Route path="/platform/overview" element={<Guard when={isPlatformAdmin(user)}><PlatformOverview/></Guard>}/>
    <Route path="/platform/model-governance" element={<Guard when={canConfigureModels(user)}><ModelGovernance lastDaysRange={lastDaysRange}/></Guard>}/>
    <Route path="/platform/agent-catalog" element={<Guard when={canManageCatalog(user)}><AgentCatalog user={user}/></Guard>}/>
    <Route path="/platform/machine-credentials" element={<Guard when={isIntegrationAdmin(user)}><MachineCredentialAdmin user={user}/></Guard>}/>
    <Route path="/platform/identity-principals" element={<Guard when={canManageUsers(user)}><PrincipalAdmin user={user}/></Guard>}/>
    <Route path="/platform/departments" element={<Guard when={["platform", "company"].includes(administrationKind(user)) && user.capabilities?.includes("organization.manage")}><DepartmentAdmin user={user}/></Guard>}/>
    <Route path="/workspace/permission-requests" element={<Guard when={user.policy_mode === "v2"}><PermissionRequests user={user}/></Guard>}/>
    <Route path="/workspace/my-permissions" element={<Guard when={user.policy_mode === "v2"}><MyPermissions user={user}/></Guard>}/>
    <Route path="/admin/permission-requests" element={<Guard when={user.policy_mode === "v2" && canManageAccessRequests(user)}><PermissionRequests user={user} review/></Guard>}/>
    <Route path="/platform/agent-factory" element={<Guard when={canDevelopAgents(user)}><AgentFactory/></Guard>}/>
    <Route path="/platform/evaluations" element={<Guard when={canUseEvaluationWorkspace(user)}><EvaluationWorkspace/></Guard>}/>
    <Route path="/platform/adapter-mappings" element={<Guard when={canDevelopAgents(user)}><AdapterMapping/></Guard>}/>
    <Route path="/admin/application" element={<Guard when={isAppAdmin(user)}><ApplicationAdmin user={user}/></Guard>}/>
    <Route path="/admin/policy-assets" element={<Guard when={canManagePolicyAssets(user)}><PolicyAssetAdmin user={user} onProjection={updatePermissionProjection}/></Guard>}/>
    <Route path="/admin/skills" element={<Guard when={canManageSkills(user)}><SkillAdmin user={user}/></Guard>}/>
    <Route path="/admin/user-access" element={<Guard when={canManageAccessRequests(user)}><UserAccessAdmin/></Guard>}/>
    <Route path="/admin/conversation-governance" element={<Guard when={canReviewConversationDeletion(user)}><ConversationGovernance/></Guard>}/>
    <Route path="/admin/integrations" element={<Guard when={isIntegrationAdmin(user)}><IntegrationAdmin/></Guard>}/>
    <Route path="/audit" element={<Guard when={canAudit(user)}><AuditPage/></Guard>}/>
    <Route path="/agent-access-required" element={<AgentAccessRequired/>}/>
    <Route path="/forbidden" element={<section className="card"><Empty title="暂无访问权限" description="当前账号没有访问该空间的权限。可切换工作空间，或向管理员申请相应权限。"/><Link className="button secondary" to="/workspace">返回工作空间</Link></section>}/>
    <Route path="*" element={<Navigate to="/workspace" replace/>}/>
  </Routes></Localized>;
}

function AgentWorkspaceRoute() {
  useLanguage(); const { agentId } = useParams(); return <Localized><AgentGuard agentID={agentId}><AgentWorkspace agentId={agentId} key={agentId}/></AgentGuard></Localized>; }

function AdministrationHome({ user }) {
  useLanguage();
  const cards = [
    ["platform", "company"].includes(administrationKind(user)) && user.capabilities?.includes("organization.manage") && { to: "/platform/departments", title: "部门管理", description: "创建部门，把本公司用户加入部门，并设置部门管理员或部门用户。" },
    canManageUsers(user) && { to: "/platform/identity-principals", title: "成员与授权", description: "查找成员，核对所属范围、岗位和资源，再预览授权差异。" },
    canManageAccessRequests(user) && { to: "/admin/permission-requests", title: "待办理申请", description: "处理当前管理范围内的权限申请，核对每项批准与拒绝结果。" },
    isSystemAdmin(user) && { to: "/system/operations", title: "系统运维", description: "查看服务状态、运行异常和平台维护事项。" },
    canConfigureModels(user) && { to: "/platform/model-governance", title: "模型治理", description: "管理模型接入、价目和可用范围。" },
  ].filter(Boolean);
  return <Localized><PageTitle eyebrow="管理员" title="管理工作台" description="先选择管理部门，再处理成员和 Agent 授权。管理身份不等于业务使用权限。"/><section className="card"><h3>{administrationKind(user) === "platform" ? "超级管理员" : administrationKind(user) === "company" ? "公司管理员" : administrationKind(user) === "department" ? "部门管理员" : "权限管理员"}</h3><p>{administrationKind(user) === "platform" ? "负责全平台管理员任命和平台管理。业务使用权限仍需独立授权。" : administrationKind(user) === "company" ? "负责公司内的部门归属、部门管理员和 Agent 使用边界。管理权限不会自动取得 Agent 运行或业务数据权限。" : "成员与 Agent 授权仅限有效管理范围；Agent 分配还受公司明确委托的清单、操作和期限约束。"}</p><Link className="button secondary" to="/workspace/my-permissions">查看我的管理范围</Link></section><section className="workspace-agent-grid">{cards.map(card => <article className="workspace-agent-card" key={card.to}><h3>{card.title}</h3><p>{card.description}</p><Link className="button primary" to={card.to}>进入办理</Link></article>)}</section>{!canManageAccessRequests(user) && administrationKind(user) === "permission" && <section className="card"><h3>当前空间没有办理权限</h3><p>请选择已委托的管理工作空间；若没有选项，请由平台管理员配置管理委托。</p></section>}</Localized>;
}

function WorkspaceHome() {
  useLanguage();
  const { user } = useAuth();
  const apps = visibleApplications(user);
  const catalog = useContext(PublishedAgentContext);
  const businessAgents = businessAgentChoices(user, catalog.items);
  if (administrationKind(user)) return <><AdministrationHome user={user}/>{businessAgents.length > 0 && <WorkspaceAgents availableItems={businessAgents}/>}</>;
  return <Localized><>
    <PageTitle eyebrow="我的工作台" title={apps.length ? "选择一个助手，开始工作" : "查看与你职责匹配的管理任务"} description={apps.length ? "先用示例完成一个小任务。结果可在运行历史中找回。" : "办理成员与权限、配置资源，或核对运行情况。入口依据当前权限显示。"} actions={<><Link className="button secondary" to="/help">快速开始</Link><Link className="button secondary" to="/workspace/history">我的运行历史</Link></>}/>
    <section className="workspace-context"><span>当前应用：<b>{user.application_name || "当前工作空间"}</b>{user.department_name && <> · {user.department_name}</>}</span><TechnicalDetails values={{ "租户编号": user.tenant_id, "部门编号": user.department_id, "应用编号": user.application_id }}/></section>
    <WorkspaceAgents/>
    {(canManageUsers(user) || canManageCatalog(user) || canConfigureModels(user) || isSystemAdmin(user)) && <section className="card management-start"><h3>常用管理任务</h3><div className="inline-actions">{canManageUsers(user) && <Link className="button secondary" to="/platform/identity-principals">为同事开通使用</Link>}{canManageCatalog(user) && <Link className="button secondary" to="/platform/agent-catalog">接入和发布助手</Link>}{canConfigureModels(user) && <Link className="button secondary" to="/platform/model-governance">配置模型资源</Link>}{isSystemAdmin(user) && <Link className="button secondary" to="/system/operations">查看运行情况</Link>}</div></section>}
    {apps.length > 1 && <details className="card application-directory"><summary>查看我的应用（{apps.length} 个）</summary><section className="app-grid">{apps.map(app => <ApplicationCard key={app.id} app={app}/>)}</section></details>}
  </></Localized>;
}

function ApplicationWorkspace() {
  useLanguage();
  const { user } = useAuth();
  return <Localized><><PageTitle eyebrow="应用工作台" title={user.application_name || "当前应用"} description="查看当前应用的已发布 Agent。运行与历史记录按你的实际授权开放。"/><WorkspaceAgents/></></Localized>;
}

function WorkspaceAgents({ availableItems } = {}) {
  useLanguage();
  const received = useContext(PublishedAgentContext);
  const catalog = availableItems ? { ...received, items: availableItems } : received;
  return <Localized><><div className="section-heading"><div><p className="eyebrow">已发布助手</p><h3>本部门的 Agent 应用</h3></div><span>{catalog.items.filter(item => item.access_status === "granted").length} 个可用 · {catalog.items.length} 个已发布</span></div>
    {catalog.loading && !catalog.initialized ? <Loading label="正在读取 Agent 目录"/> : catalog.error ? <ErrorPanel error={catalog.error} retry={catalog.reload}/> : !catalog.items.length ? <section className="card"><Empty title="当前应用暂无已发布 Agent" description="可切换到业务应用；Agent 发布并安装到此应用后会显示在这里。"/></section> : <section className="workspace-agent-grid">{[...catalog.items].sort((a, b) => Number(b.access_status === "granted") - Number(a.access_status === "granted")).map(item => { const presentation = agentPresentation(item); const granted = item.access_status === "granted"; return <article className="workspace-agent-card" key={item.installation_id || item.agent_id}><div className="card-heading"><span className="app-icon"><NavigationIcon name="V"/></span><span className={`badge ${granted ? "success" : "neutral"}`}>{granted ? "可使用" : "需申请权限"}</span></div><h3>{presentation.name}</h3><p>{presentation.description}</p><small>版本 {item.semantic_version}</small><TechnicalDetails values={{ "智能体编号": item.agent_id, "安装编号": item.installation_id }}/><Link className={`button ${granted ? "primary" : "secondary"}`} to={agentWorkspacePath(item)}>{granted ? "开始使用" : "查看与申请权限"}<span aria-hidden="true"> →</span></Link></article>; })}</section>}
  </></Localized>;
}

function NavigationIcon({ name }) {
  useLanguage();
  const paths = { "⌂": "M3 10 12 3l9 7v10H3V10Zm6 10v-7h6v7", "信": "M18 8a6 6 0 0 0-12 0v6l-2 3h16l-2-3V8Zm-8 12h4", "menu": "M4 6h16M4 12h16M4 18h16", "logout": "M10 4H4v16h6m5-13 5 5-5 5m-7-5h12", "权": "M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Zm-4 9 3 3 5-6", "S": "M4 5h16v14H4V5Zm0 10h16m-9 3h2", "I": "M8 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm-5 9v-2a5 5 0 0 1 10 0v2m4-14a3 3 0 0 1 0 6m0 3a5 5 0 0 1 4 5", "F": "m8 7-5 5 5 5m8-10 5 5-5 5m-3-13-2 16", "M": "M5 5h14v14H5V5Zm4 4h6v6H9V9m-6-1H1m2 8H1m20-8h2m-2 8h2M8 3V1m8 2V1M8 21v2m8-2v2", "申": "M6 3h9l3 3v15H6V3Zm3 7h6m-6 4h6m-6 4h4", "◎": "M3 5h18v15H3V5Zm4 4h10M7 13h6m-6 4h8" };
  return <Localized><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name] || "M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z"}/></svg></Localized>;
}

function ApplicationCard({ app }) {
  useLanguage(); return <Localized><Link to={app.path} className={`application-card ${app.accent}`}><div className="app-icon">合</div><div><span>{app.departmentName}</span><h3>{app.name}</h3><p>{app.description}</p><div className="agent-tags">{app.agents.map((agent) => <i key={agent}>{agent}</i>)}</div></div><b className="arrow">→</b></Link></Localized>; }

function SystemOperations() {
  useLanguage();
  const { user } = useAuth();
  const range = useMemo(() => lastDaysRange(7), []);
  const [page, setPage] = useState(1);
  const [steps, setSteps] = useState({});
  const remote = useRemote(async () => { const [status, runs] = await Promise.all([api.opsStatus(), api.usageRuns({ ...range, page, page_size: 20 })]); return { status, runs }; }, [page]);
  const loadSteps = async (runID) => {
    try {
      const result = await api.usageRunSteps(runID, { ...range, page: 1, page_size: 100 });
      setSteps((current) => ({ ...current, [runID]: { items: asItems(result), total: result.total } }));
    } catch (error) {
      setSteps((current) => ({ ...current, [runID]: { error: error.message } }));
    }
  };
  if (remote.loading) return <Localized><Loading label="正在检查平台组件"/></Localized>;
  if (remote.error) return <Localized><ErrorPanel error={remote.error} retry={remote.reload}/></Localized>;
  const value = remote.data.status;
  const runs = asItems(remote.data.runs);
  const runTotal = Number(remote.data.runs?.total || 0);
  return <Localized><><PageTitle eyebrow="运行与运维" title="系统运维中心" description="面向科技运维的部署状态、可观测入口与审计定位空间。" actions={<button className="button secondary" onClick={remote.reload}>刷新状态</button>}/>
    {value.model_mode === "mock" && <div className="notice"><b>平台默认模型配置为 Mock</b><p>此字段来自平台默认配置。各助手实际使用的模型由已发布策略和实际调用记录决定；默认配置不能证明本次调用使用了 Mock。</p></div>}
    <section className="metric-grid"><Metric label="部署 Profile" value={value.profile} hint="当前运行环境" tone="violet"/><Metric label="Frontend Gateway" value={value.gateway.status} hint={value.gateway.version}/><Metric label="Platform" value={value.platform.status} hint={`${value.platform.latency_ms} ms`} tone="green"/></section>
    <section className="two-column"><article className="card"><div className="card-heading"><h3>组件健康</h3><Badge value={value.platform.status}/></div><div className="component-list">{value.components.map((item) => <div key={item.name}><i className={item.status}/><span><b>{item.name}</b><small>{item.endpoint}</small></span><Badge value={item.status}/></div>)}</div></article><article className="card"><h3>运维边界</h3><div className="notice"><b>当前显示的是实时 readiness 探测结果</b><p>组件状态来自已部署的 Frontend Gateway 和平台健康检查；它不代表 Kubernetes 控制面、告警或灾备已接入。生产运维能力需按生产准出单独部署与验收。</p></div><div className="action-grid compact">{canAudit(user) && <Link to="/audit"><b>审计查询</b><p>按 task / trace 定位调用链。</p></Link>}<Link to="/platform/overview"><b>平台用量</b><p>查看 Provider 与 Token 台账。</p></Link></div></article></section>
    <section className="card"><div className="card-heading"><div><p className="eyebrow">按任务查看用量</p><h3>近 7 日 Agent Run 计费明细</h3></div><span>按持久用量账本聚合；步骤只包含计费事件</span></div>{runs.length ? <div className="execution-usage-list">{runs.map((run) => <article key={run.run_id} className="card"><div className="card-heading"><span><b>{run.scope?.agent_id} · {run.scope?.agent_version_id}</b><small>Run：{run.run_id} · {run.event_count} 条计费事件 · {formatTime(run.first_usage_at)}—{formatTime(run.last_usage_at)}</small></span><strong>{Number(run.input_tokens || 0) + Number(run.output_tokens || 0)} Tokens</strong></div><div className="execution-total-grid"><span>输入 <b>{run.input_tokens}</b></span><span>输出 <b>{run.output_tokens}</b></span><span>成本 <b>{run.cost_micros} 微元</b></span></div><button type="button" className="button secondary" onClick={() => loadSteps(run.run_id)}>查看计费事件</button>{steps[run.run_id]?.error && <div className="form-error">{steps[run.run_id].error}</div>}{steps[run.run_id]?.items && <div className="simple-table">{steps[run.run_id].items.map((step) => <div key={step.event_id}><span><b>{step.provider} / {step.model}</b><small>#{step.index} · {formatTime(step.occurred_at)} · {step.event_id}</small></span><span>输入 {step.input_tokens} + 输出 {step.output_tokens} · {step.cost_micros} 微元</span></div>)}{steps[run.run_id].total > 100 && <div>显示前 100 条计费事件，共 {steps[run.run_id].total} 条。</div>}</div>}</article>)}</div> : <Empty title="近 7 日暂无计费记录" description="Agent 产生模型或 Embedding 计费事件后会显示。"/>}<div className="inline-actions"><button type="button" className="button secondary" disabled={page <= 1} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page} 页 · 共 {runTotal} 个 Run</span><button type="button" className="button secondary" disabled={page * 20 >= runTotal} onClick={() => setPage(page + 1)}>下一页</button></div></section></></Localized>;
}

function PlatformOverview() {
  useLanguage();
  const { user } = useAuth();
  const range = useMemo(() => lastDaysRange(7), []);
  const [organizationNotice, setOrganizationNotice] = useState("");
  const [organizationError, setOrganizationError] = useState("");
  const remote = useRemote(async () => {
    const [tenants, departments, applications, models, usage] = await Promise.all([api.tenants(), api.departmentPage({ tenant_id: user.tenant_id, page: 1, page_size: 20 }), api.applications(), api.modelDefinitions({ limit: 100 }), api.usageAggregate(range)]);
    return { tenants: asItems(tenants), departments: asItems(departments), departmentTotal: departments.total, applications: asItems(applications), models: asItems(models), usage };
  }, []);
  if (remote.loading) return <Localized><Loading/></Localized>;
  if (remote.error) return <Localized><ErrorPanel error={remote.error} retry={remote.reload}/></Localized>;
  const summary = { total: Number(remote.data.usage?.input_tokens || 0) + Number(remote.data.usage?.output_tokens || 0), requests: Number(remote.data.usage?.event_count || 0) };
  const createOrganization = async (event, action, success) => { event.preventDefault(); const form = event.currentTarget; setOrganizationError(""); try { await action(Object.fromEntries(new FormData(form))); setOrganizationNotice(success); form.reset(); remote.reload(); } catch (error) { setOrganizationError(error.message); } };
  return <Localized><><PageTitle eyebrow="平台治理" title="平台管理中心" description="统一治理组织、模型目录、Agent 安装和平台用量。"/>
    {organizationNotice && <div className="success-banner">{organizationNotice}</div>}{organizationError && <div className="form-error page-error">{organizationError}</div>}
    <section className="metric-grid"><Metric label="租户 / 部门" value={`${remote.data.tenants.length} / ${remote.data.departmentTotal ?? remote.data.departments.length}`} hint="平台组织树" tone="violet"/><Metric label="Model Definition" value={remote.data.models.length} hint="当前页全局模型目录"/><Metric label="应用" value={remote.data.applications.length} hint="当前管理作用域" tone="cyan"/><Metric label="近 7 日计量" value={summary.total} hint={`${summary.requests} 条持久计费事件`} tone="green"/></section>
    <section className="two-column"><article className="card"><h3>创建租户</h3><form id="create-tenant-form" className="inline-form" onSubmit={(event) => createOrganization(event, api.createTenant, "租户已创建")}><input name="code" placeholder="租户编码" required/><input name="name" placeholder="租户名称" required/><button className="button primary">创建</button></form><div className="record-list">{remote.data.tenants.map((item) => <div key={item.id}><span className="record-icon">T</span><span><b>{item.name}</b><small>{item.code} · {shortId(item.id)}</small></span><Badge value={item.status}/></div>)}</div></article>
    <article className="card"><h3>部门管理</h3><p>创建部门，再添加成员并指定部门身份。没有 Agent 的部门也可先配置成员。</p>{["platform", "company"].includes(administrationKind(user)) && user.capabilities?.includes("organization.manage") && <Link className="button primary" to="/platform/departments">部门管理</Link>}<div className="record-list">{remote.data.departments.map((item) => <div key={item.id}><span className="record-icon">D</span><span><b>{item.name}</b><TechnicalDetails values={{ "部门编号": item.id, "部门编码": item.code }}/></span><Badge value={item.status}/></div>)}</div></article></section>
    <section className="two-column"><article className="card"><h3>当前管理作用域应用</h3>{remote.data.applications.length ? <div className="record-list">{remote.data.applications.map((item) => <div key={item.id}><span className="record-icon">A</span><span><b>{item.name}</b><small>{item.code} · {shortId(item.id)}</small></span><Badge value={item.status}/></div>)}</div> : <Empty title="当前管理部门暂无应用" description="部门管理员在自己的身份作用域内创建应用。"/>}</article><article className="card"><h3>全局模型目录</h3><div className="simple-table model-profile-list">{remote.data.models.map((item) => <div key={item.id}><span><b>{item.display_name} · {item.model_key}</b><small>Provider ID：{item.provider_id} · {item.kind} · context {item.context_limit}</small><small>状态：{item.lifecycle_status} · revision {item.revision}</small></span></div>)}</div>{!remote.data.models.length && <Empty title="暂无 Model Definition" description="请在模型治理中心登记 Provider 与 Model。"/>}<Link to="/platform/model-governance" className="button secondary">进入模型治理中心</Link></article></section>
    <section className="card"><h3>Agent 发布与部署管理</h3><p className="form-hint">Agent Version、Installation 和 Deployment 的受控生命周期由当前 Catalog Module 管理；不再提供旧 Harness Runtime Binding 直写入口。</p><Link to="/platform/agent-catalog" className="button secondary">进入 Agent 目录与安装</Link></section></></Localized>;
}

function UserAccessAdmin() {
  useLanguage();
	const { user } = useAuth();
	const [approval, setApproval] = useState(null);
	const [rejection, setRejection] = useState(null);
  const [status, setStatus] = useState("pending_review");
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const enrollmentRemote = useRemote(() => loadEnrollmentReview(api, status), [status]);
  const agentAccessRemote = useRemote(() => loadAgentAccessReview(api, user.policy_mode), [user.policy_mode]);
  const approve = async (event, item) => {
    event.preventDefault(); setActionError("");
	if (user.policy_mode === "v2") { setRejection(null); setApproval(item); return; }
    const form = event.currentTarget;
    const selectedInstances = Array.from(form.querySelectorAll('input[name="agent_instance_id"]:checked')).map((input) => input.value);
    if (!selectedInstances.length) { setActionError("批准时至少选择一个 Agent 安装实例"); return; }
    const catalog = agentAccessRemote.data?.catalog || [];
    try {
      const grants = selectedInstances.map((instanceID) => {
        const agent = catalog.find((candidate) => candidate.installation_id === instanceID);
        if (!agent || !item.requested_agent_ids?.includes(agent.agent_id)) throw new Error("所选安装实例不属于该申请的期望 Agent");
        return { agent_instance_id: instanceID, actions: ["discover", "run", "history.read", "history.export", "history.delete.request", "cancel"] };
      });
      await api.approveEnrollment(item.id, { expected_revision: item.revision, grants, comment: new FormData(form).get("reason") }); setNotice(`${item.display_name} 已激活，所选 Agent 权限立即生效。`); enrollmentRemote.reload();
    }
    catch (error) { setActionError(error.message); }
  };
  const reject = async (item) => { if (user.policy_mode === "v2") { setApproval(null); setRejection(item); return; } const comment = prompt(translateUI("请输入可向申请人公开的拒绝原因")); if (!comment) return; setActionError(""); try { await api.rejectEnrollment(item.id, { expected_revision: item.revision, comment }); setNotice("申请已拒绝并留痕。"); enrollmentRemote.reload(); } catch (error) { setActionError(error.message); } };
  const decideAccess = async (item, approved) => { const comment = prompt(translateUI(approved ? "请输入批准理由" : "请输入拒绝理由")); if (!comment) return; setActionError(""); try { await api.decideIdentityAgentAccessRequest(item.id, approved ? "approve" : "reject", { expected_revision: item.revision, comment }); setNotice(approved ? "Agent 权限已授予并立即生效。" : "权限申请已拒绝。"); agentAccessRemote.reload(); } catch (error) { setActionError(error.message); } };
  return <Localized><><PageTitle eyebrow="用户开通与授权" title="用户与 Agent 授权" description="审批普通用户入驻，并按当前已发布 Agent 动态授予最小权限。新增 Agent 发布后会自动进入授权清单。"/>
    {approval && <EnrollmentPermissionApproval key={approval.id} item={approval} catalog={agentAccessRemote.data?.catalog || []} onClose={() => setApproval(null)} onSaved={async () => { setNotice(`${approval.display_name} 的账号已激活。`); enrollmentRemote.reload(); }}/>}
    {rejection && <EnrollmentRejection key={rejection.id} item={rejection} onClose={() => setRejection(null)} onSaved={async () => { setNotice("入驻申请已拒绝并留痕。"); enrollmentRemote.reload(); }}/>}
    {notice && <div className="success-banner">{notice}</div>}{actionError && <div className="form-error page-error">{actionError}</div>}
    <section className="card"><div className="card-heading"><div><h3>注册申请</h3><p>审批使用修订号 CAS；两个管理员并发操作时只有一个会成功。</p></div><label><span>状态</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="pending_review">待审批</option><option value="contact_verification_pending">待验证联系方式</option><option value="approved">已通过</option><option value="rejected">已拒绝</option><option value="withdrawn">已撤回</option><option value="">全部</option></select></label></div>
      {enrollmentRemote.loading ? <Loading/> : enrollmentRemote.error ? <ErrorPanel error={enrollmentRemote.error} retry={enrollmentRemote.reload}/> : enrollmentRemote.data.length ? <div className="enrollment-list">{enrollmentRemote.data.map((item) => <article key={item.id} className="enrollment-item"><div className="card-heading"><div><b>{item.display_name} · {item.username}</b><small>{item.contact} · {formatTime(item.created_at)} · r{item.revision}</small></div><Badge value={item.status}/></div><p>{item.reason}</p><small>申请偏好：{Array.isArray(item.requested_agent_ids) ? item.requested_agent_ids.join("、") || "未指定" : "未指定"}</small>{item.status === "pending_review" && <form className="form" onSubmit={(event) => approve(event, item)}><fieldset><legend>授予可使用的 Agent 安装实例</legend>{agentAccessRemote.data?.catalog.filter((agent) => item.requested_agent_ids?.includes(agent.agent_id)).map((agent) => <label className="checkbox-row" key={agent.installation_id}><input name="agent_instance_id" type="checkbox" value={agent.installation_id}/><span>{agent.name} · {agent.semantic_version} · {agent.installation_id}</span></label>)}</fieldset><label><span>审批理由</span><input name="reason" defaultValue="岗位职责需要，经核验批准" minLength="2" required/></label><div className="inline-actions"><button className="button primary">批准并激活</button><button className="button secondary" type="button" onClick={() => reject(item)}>拒绝</button></div></form>}</article>)}</div> : <Empty title="当前状态没有申请" description="新申请提交后会自动出现在这里。"/>}
    </section>
    {user.policy_mode === "v2" ? <section className="card"><h3>角色与 Agent 权限申请</h3><p className="form-hint">账号入驻与使用权限分别办理。用户提交的岗位、Agent 和操作申请可在统一审批页面逐项处理。</p><Link className="button secondary" to="/admin/permission-requests">进入角色与资源审批</Link></section> : <section className="card"><div className="card-heading"><div><h3>Agent 权限申请</h3><p>处理已登录用户对锁定 Agent 发起的权限申请；批准将创建精确到当前安装实例的 Identity Grant。</p></div></div>{agentAccessRemote.loading ? <Loading/> : agentAccessRemote.error ? <ErrorPanel error={agentAccessRemote.error} retry={agentAccessRemote.reload}/> : agentAccessRemote.data.accessRequests?.filter((item)=>item.status==="pending").length ? <div className="record-list">{agentAccessRemote.data.accessRequests.filter((item)=>item.status==="pending").map((item)=><div key={item.id}><span><b>{item.subject_id} · {item.agent_id}</b><small>安装实例：{item.agent_instance_id} · {item.reason} · {formatTime(item.created_at)} · r{item.revision}</small></span><div className="inline-actions"><button className="button primary" onClick={()=>decideAccess(item,true)}>批准</button><button className="button secondary" onClick={()=>decideAccess(item,false)}>拒绝</button></div></div>)}</div> : <Empty title="暂无待处理权限申请" description="用户从锁定 Agent 页面提交后会显示在这里。"/>}</section>}</></Localized>;
}

function ConversationGovernance() {
  useLanguage();
  const {user,updatePermissionProjection}=useAuth(); const [notice,setNotice]=useState(""); const [query,setQuery]=useState(""); const [searchKind,setSearchKind]=useState("qa"); const [results,setResults]=useState([]);
  const search=async(event)=>{event.preventDefault();try{const result=await api.globalConversationSearch({kind:searchKind,q:query,page:1,page_size:50});setResults(asItems(result));setNotice(`检索完成，共 ${result.total} 条匹配摘要。`)}catch(error){setNotice(error.message)}};
  return <Localized><><PageTitle eyebrow="会话管理" title="会话治理" description="删除申请由不同人员审批；列表和操作受当前授权范围约束。"/>{notice&&<div className="notice">{notice}</div>}<ConversationDeletionReview user={user} onProjection={updatePermissionProjection}/>{isPlatformAdmin(user)&&<section className="card"><h3>跨应用 / 跨租户会话摘要检索</h3><form className="inline-form" onSubmit={search}><select value={searchKind} onChange={(e)=>setSearchKind(e.target.value)}><option value="qa">问答会话</option><option value="check">工作流任务</option></select><input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder={searchKind==="qa"?"标题或脱敏预览关键词":"运行 ID 或业务关键词"}/><button className="button primary">检索</button></form><div className="record-list">{results.map((item)=><div key={`${item.kind}-${item.id}`}><span><b>{item.title} · {item.agent_id}</b><small>{item.owner_id} · {formatTime(item.started_at)}</small></span></div>)}</div></section>}</></Localized>;
}

function ApplicationAdmin({ user }) {
  useLanguage();
  return <Localized><>
    <PageTitle eyebrow="应用管理" title="应用与 Agent 管理" description="部门管理员在本部门创建、停用应用；应用管理员仅管理当前应用内 Agent 与策略。"/>
    <ApplicationDirectory user={user}/>
    <ApplicationAgentInstallations user={user}/>
    <ApplicationGovernancePanel user={user}/>
  </></Localized>;
}

function ApplicationDirectory({ user }) {
  useLanguage();
  const pageSize = 10;
  const [page, setPage] = useState(1);
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const remote = useRemote(() => api.applications({ department_id: user.department_id, page, page_size: pageSize }), [user.tenant_id, user.department_id, user.application_id, page]);
  const canManageApplications = isPlatformAdmin(user) || rolesOf(user).includes("department_admin");
  const applications = asItems(remote.data);
  const total = Number(remote.data?.total ?? applications.length);
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const create = async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setActionError("");
    try {
      await api.createApplication(applicationCreateCommand(Object.fromEntries(new FormData(form)), user));
      setNotice("应用已创建");
      form.reset();
      setPage(1);
      remote.reload();
    } catch (error) {
      setActionError(error.message);
    }
  };
  const disable = async (application) => {
    setActionError("");
    try {
      await api.disableApplication(application.id, application.department_id, application.revision);
      setNotice(`${application.name} 已停用；历史记录保留，后续创建安装将被拒绝。`);
      remote.reload();
    } catch (error) {
      setActionError(error.message);
      remote.reload();
    }
  };

  return <Localized><section className="card organization-application-directory">
    <div className="card-heading"><div><h3>应用目录</h3><p>应用权限按认证会话的租户与部门作用域执行；列表使用服务端分页和总数。</p></div><span>{total} 个应用</span></div>
    {notice && <div className="success-banner">{notice}</div>}
    {actionError && <div className="form-error" role="alert">{actionError}</div>}
    {canManageApplications && <form className="inline-form" onSubmit={create} id="create-app-form"><input name="code" placeholder="应用编码" required/><input name="name" placeholder="应用名称" required/><button className="button primary">创建应用</button></form>}
    {!canManageApplications && <p className="form-hint">应用管理员可管理当前应用中的 Agent；新增或停用应用由部门/平台管理员执行。</p>}
    {remote.loading ? <Loading label="正在读取作用域内应用"/> : remote.error ? <ErrorPanel error={remote.error} retry={remote.reload}/> : applications.length ? <div className="record-list">{applications.map((item) => <div key={item.id}><span className="record-icon">A</span><span><b>{item.name}</b><small>{item.code} · {item.id} · revision {item.revision}</small></span><Badge value={item.status}/>{canManageApplications && item.status === "active" && <button className="button secondary" type="button" onClick={() => disable(item)}>停用</button>}</div>)}</div> : <Empty title="当前作用域暂无应用" description="创建应用后，它会出现在此目录中。"/>}
    {!remote.loading && !remote.error && pageCount > 1 && <div className="inline-actions pagination-controls"><button className="button secondary" type="button" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {page} / {pageCount} 页 · 共 {total} 个</span><button className="button secondary" type="button" disabled={page >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div>}
  </section></Localized>;
}

function ApplicationGovernancePanel({ user }) {
  useLanguage();
  const isPlatformOperator = isPlatformAdmin(user);
  const modules = [
    {
      title: "Agent 目录、版本发布与部署",
      detail: "平台 Agent Definition、不可变 Version、评测发布、Installation 与 observed-ready Deployment 均由 Catalog 模块管理。",
      href: "/platform/agent-catalog",
      available: canManageCatalog(user),
      owner: "平台管理员"
    },
    {
      title: "模型与 Provider 治理",
      detail: "Provider 注册与审批、Model Definition/Version、Deployment 期望配置和持久用量查询由 Model Governance 管理。",
      href: "/platform/model-governance",
      available: canConfigureModels(user),
      owner: "平台管理员"
    },
    {
      title: "六类应用策略资产",
      detail: "当前应用 Agent 的 Model、Prompt、Tool、Memory、Knowledge、Runtime 资产及原子快照在独立策略资产模块管理。",
      href: "/admin/policy-assets",
      available: canManagePolicyAssets(user),
      owner: "应用管理员"
    },
    {
      title: "Agent 模板工厂",
      detail: "模板 Definition/Version、制品登记、兼容性和映射绑定由 Agent Factory 管理。",
      href: "/platform/agent-factory",
      available: canDevelopAgents(user),
      owner: "Agent 开发者"
    },
    {
      title: "Adapter 映射",
      detail: "声明式 Adapter 映射、兼容性 Dry-run 与发布在独立 Adapter Mapping 模块管理。",
      href: "/platform/adapter-mappings",
      available: canDevelopAgents(user),
      owner: "Agent 开发者"
    },
    {
      title: "Agent 评测工作台",
      detail: "数据集、评测套件、运行记录、证据与评测门禁由独立 Evaluation Product 模块管理。",
      href: "/platform/evaluations",
      available: canUseEvaluationWorkspace(user),
      owner: "具备评测工作台权限的管理员"
    }
  ];
  return <Localized><section className="card" aria-label="Agent 治理模块导航">
    <div className="card-heading"><div><h3>Agent 治理模块</h3><p className="form-hint">治理能力已拆分到各自的受权限保护模块；本页不再直接写入旧版 Model/Prompt/Tool/Policy API。</p></div></div>
    <div className="two-column">
      {modules.map((module) => <article className="card" key={module.href}>
        <h4>{module.title}</h4>
        <p>{module.detail}</p>
        {module.available
          ? <Link className="button secondary" to={module.href}>打开{module.title}</Link>
          : <p className="form-hint">需要{module.owner}权限；请联系平台管理员开通。此能力没有被移除，当前身份不能进入对应管理模块。</p>}
      </article>)}
    </div>
    {!isPlatformOperator && <div className="notice" style={{ marginTop: 14 }}>
      <b>应用管理员的边界</b>
      <p>上方“应用策略资产”供当前应用管理员使用。消费已发布 Agent 和查看/管理本应用 Installation 请使用本页上方的“应用 Agent 安装”区域；Definition、Version 发布及 Deployment 期望状态由平台管理员通过 Catalog 管理。</p>
    </div>}
  </section></Localized>;
}

function IntegrationAdmin() {
  useLanguage();
  const { user } = useAuth();
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const [selectedInstallation, setSelectedInstallation] = useState("");
  const [grants, setGrants] = useState([]);
  const [decision, setDecision] = useState(null);
  const scope = { tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id };
  const tenantWide = isPlatformAdmin(user);
  const remote = useRemote(async () => {
    const [installations, principals] = await Promise.all([
      api.catalogInstallations(tenantWide ? { tenant_id: user.tenant_id } : scope, { limit: 100 }),
      api.identityPrincipals({ tenant_id: user.tenant_id, principal_type: "service_principal" })
    ]);
    return { installations: asItems(installations), principals: asItems(principals) };
  }, [user.tenant_id, user.department_id, user.application_id, tenantWide]);
  const selected = remote.data?.installations.find((item) => item.id === selectedInstallation);
  useEffect(() => {
    if (!remote.data) return;
    setSelectedInstallation((current) => remote.data.installations.some((item) => item.id === current) ? current : (remote.data.installations[0]?.id || ""));
  }, [remote.data]);
  useEffect(() => {
    let active = true;
    if (!selected) { setGrants([]); return () => { active = false; }; }
    const targetScope = { tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id };
    api.identityGrants({ ...targetScope, subject_type: "service_principal" })
      .then((result) => { if (active) setGrants(asItems(result)); })
      .catch((error) => { if (active) setActionError(error.message); });
    return () => { active = false; };
  }, [selectedInstallation, remote.data]);
  const runAction = async (action) => { setActionError(""); try { await action(); } catch (error) { setActionError(error.message); } };
  const createPrincipal = (event) => { event.preventDefault(); const form = event.currentTarget; runAction(async () => { const values = Object.fromEntries(new FormData(form)); await api.createIdentityPrincipal({ type: "service_principal", id: String(values.principal_id).trim(), tenant_id: user.tenant_id, is_active: true, roles: [], groups: [] }); setNotice("外部系统主体已登记。请为其逐个 Agent Installation 创建最小权限 Grant。"); form.reset(); await remote.reload(); }); };
  const createGrant = (event) => { event.preventDefault(); const form = event.currentTarget; runAction(async () => { const values = Object.fromEntries(new FormData(form)); if (!selected) throw new Error("请选择目标 Agent Installation"); const principal = remote.data.principals.find((item) => item.id === values.subject_id); if (!principal) throw new Error("请选择已登记的机器主体"); await api.createIdentityGrant({ id: crypto.randomUUID(), tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id, subject_type: "service_principal", subject_id: principal.id, action: values.action, effect: values.effect, status: "active", revision: 1 }); setNotice("最小权限 Grant 已创建；授权由服务端 Identity 在每次运行时重新判定。"); form.reset(); const targetScope = { tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id, subject_type: "service_principal" }; setGrants(asItems(await api.identityGrants(targetScope))); }); };
  const revokeGrant = (item) => runAction(async () => { if (!selected) throw new Error("请选择目标 Agent Installation"); await api.revokeIdentityGrant(item.id, { tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id }, item.revision); setNotice("Grant 已撤销，新请求会按最新状态拒绝。"); setGrants(asItems(await api.identityGrants({ tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id, subject_type: "service_principal" }))); });
  const explainGrant = (event) => { event.preventDefault(); const values = Object.fromEntries(new FormData(event.currentTarget)); runAction(async () => { if (!selected) throw new Error("请选择目标 Agent Installation"); setDecision(await api.identityExplainGrant({ scope: { tenant_id: selected.tenant_id, department_id: selected.department_id, application_id: selected.application_id, agent_instance_id: selected.id }, principal_type: "service_principal", principal_id: values.subject_id, action: values.action })); }); };
  if (remote.loading) return <Localized><Loading label="正在读取外部系统接入配置"/></Localized>;
  if (remote.error) return <Localized><ErrorPanel error={remote.error} retry={remote.reload}/></Localized>;
  const activeGrants = grants.filter((item) => item.status === "active" && item.effect === "allow");
  return <Localized><><PageTitle eyebrow="外部系统身份" title="外部系统接入" description="登记外部系统机器主体，并按租户、应用、Agent Installation 和动作授予最小权限。授权只由 Identity 模块维护。"/>{notice && <div className="success-banner">{notice}</div>}{actionError && <div className="form-error page-error">{actionError}</div>}
    <section className="metric-grid"><Metric label={tenantWide ? "租户 Agent Installation" : "当前应用 Installation"} value={remote.data.installations.length} hint={tenantWide ? "平台管理员范围" : `${scope.department_id} / ${scope.application_id}`} tone="violet"/><Metric label="机器身份" value={remote.data.principals.length} hint="Identity Service Principal" tone="cyan"/><Metric label="活动允许 Grant" value={activeGrants.length} hint="按 Installation 与动作精确匹配" tone="green"/><Metric label="默认权限" value="Deny" hint="无匹配 Grant 即拒绝"/></section>
    <section className="two-column"><article className="card"><h3>1. 登记外部系统机器主体</h3><form id="create-principal-form" className="form" onSubmit={createPrincipal}><label><span>稳定主体 ID</span><input name="principal_id" placeholder="例如：aml-batch-prod" required maxLength="128"/></label><button className="button primary">登记机器主体</button></form><div className="record-list">{remote.data.principals.map((item) => <div key={item.id}><span className="record-icon">M</span><span><b>{item.id}</b><small>{item.tenant_id} · {item.type} · {item.is_active ? "active" : "disabled"}</small></span><Badge value={item.is_active ? "active" : "disabled"}/></div>)}</div><p className="form-hint">此步骤仅登记受信任的机器主体。平台管理员在“机器身份凭证”页签发一次性 Secret，并按最小范围配置来源 CIDR；机器调用再以 client_credentials 换取短时 Token。</p></article>
    <article className="card"><h3>2. 精确授予 Agent 使用权</h3><label><span>目标 Agent Installation</span><select value={selectedInstallation} onChange={(event) => { setSelectedInstallation(event.target.value); setDecision(null); }}><option value="">选择 Agent Installation</option>{remote.data.installations.map((item) => <option key={item.id} value={item.id}>{item.display_name} · {item.application_id} · {item.id}</option>)}</select></label><form id="create-grant-form" className="form" onSubmit={createGrant}><label><span>外部系统主体</span><select name="subject_id" required defaultValue=""><option value="">选择已登记机器主体</option>{remote.data.principals.map((item) => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label><label><span>允许动作</span><select name="action" defaultValue="run"><option value="discover">discover</option><option value="invoke">invoke</option><option value="run">run</option><option value="resume">resume</option><option value="cancel">cancel</option><option value="events">events</option></select></label><label><span>授权效果</span><select name="effect" defaultValue="allow"><option value="allow">允许</option><option value="deny">拒绝</option></select></label><button className="button primary" disabled={!selected || remote.data.principals.length === 0}>保存最小权限 Grant</button></form></article></section>
    <section className="two-column"><article className="card"><div className="card-heading"><h3>当前 Installation 授权台账</h3><span>{grants.length} 条</span></div><div className="simple-table">{grants.map((item) => <div key={item.id}><span><b>{item.subject_type} · {item.subject_id}</b><small>{item.agent_instance_id} · {item.action} · {item.effect}</small></span><span><Badge value={item.status}/>{item.status === "active" && <button className="button secondary danger" onClick={() => revokeGrant(item)}>撤销</button>}</span></div>)}</div>{!selected && <Empty title="请选择 Installation" description="选择后查看该 Agent 的机器身份授权。"/>}</article>
    <article className="card"><h3>3. 服务端解释授权</h3><form className="form" onSubmit={explainGrant}><label><span>机器主体</span><select name="subject_id" required defaultValue=""><option value="">选择机器主体</option>{remote.data.principals.map((item) => <option key={item.id} value={item.id}>{item.id}</option>)}</select></label><label><span>检查动作</span><select name="action" defaultValue="run"><option value="discover">discover</option><option value="invoke">invoke</option><option value="run">run</option><option value="resume">resume</option><option value="cancel">cancel</option><option value="events">events</option></select></label><button className="button secondary" disabled={!selected}>解释授权</button></form>{decision && <div className="notice"><b>{decision.allowed ? "ALLOW" : "DENY"}</b><p>{decision.reason || "默认拒绝"}</p></div>}<p className="form-hint">解释结果使用与运行时相同的 Identity 授权规则；它不是调用凭据，也不会绕过 Agent Runtime。</p></article></section></></Localized>;
}

function AuditPage() {
  useLanguage();
  const { user } = useAuth();
  const [query, setQuery] = useState({ scope_type: "application", tenant_id: user.tenant_id, department_id: user.department_id, application_id: user.application_id, task_id: "", trace_id: "" });
  const [items, setItems] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const generation = useRef(0);
  const updateQuery = (patch) => { generation.current++; setQuery((current) => ({ ...current, ...patch })); setItems([]); setTotal(0); setPage(1); setError(""); setLoading(false); };
  const load = async (nextPage) => {
    const current = ++generation.current;
    setLoading(true); setItems([]); setError("");
    try {
      const result = await api.audits(auditMetadataQuery(query, nextPage));
      if (current !== generation.current) return;
      setItems(asItems(result)); setTotal(Number(result.total || 0)); setPage(Number(result.page || nextPage));
    } catch (reason) { if (current === generation.current) { setError(reason.message); setTotal(0); } }
    finally { if (current === generation.current) setLoading(false); }
  };
  const submit = (event) => { event.preventDefault(); load(1); };
  const scopeTypes = user.policy_mode === "v2" ? [["global", "全平台"], ["tenant", "租户"], ["department", "部门"], ["application", "应用"]] : [["application", "当前应用"]];
  return <Localized><><PageTitle eyebrow="审计与追踪" title="审计查询" description="查询被授权范围内的操作元数据；业务正文、敏感摘要与导出需要独立授权。"/>
    <section className="card"><form id="audit-filter" className="filter-form audit-filter" onSubmit={submit}>
      <label><span>范围</span><select value={query.scope_type} onChange={(event) => updateQuery({ scope_type: event.target.value })}>{scopeTypes.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      {query.scope_type !== "global" && <label><span>租户 ID</span><input value={query.tenant_id} onChange={(event) => updateQuery({ tenant_id: event.target.value })}/></label>}
      {["department", "application"].includes(query.scope_type) && <label><span>部门 ID</span><input value={query.department_id} onChange={(event) => updateQuery({ department_id: event.target.value })}/></label>}
      {query.scope_type === "application" && <label><span>应用 ID</span><input value={query.application_id} onChange={(event) => updateQuery({ application_id: event.target.value })}/></label>}
      <label><span>Task ID（可选）</span><input value={query.task_id} onChange={(event) => updateQuery({ task_id: event.target.value })}/></label>
      <label><span>Trace ID（可选）</span><input value={query.trace_id} onChange={(event) => updateQuery({ trace_id: event.target.value })}/></label>
      <button className="button primary" disabled={loading}>{loading ? "查询中…" : "查询审计"}</button>
    </form>{error && <div className="form-error">{error}</div>}
    {items.length ? <ol className="audit-list">{items.map((item) => <li key={item.id}><i/><div><b>{item.action}</b><small>{formatTime(item.created_at)} · Trace {item.trace_id || "—"}</small><p>{item.tenant_id} / {item.department_id} / {item.application_id} · {item.aggregate_type} · {item.aggregate_id} · {item.outcome || "—"}</p><AuditEventContent key={`${user.id}:${user.tenant_id}:${user.department_id}:${user.application_id}:${item.id}`} eventID={item.id}/></div></li>)}</ol> : <Empty title={loading ? "正在查询" : "暂无审计事件"} description="选择范围后查询，可用 Task ID 或 Trace ID 筛选。"/>}
    <div className="filter-form"><span>共 {total} 条 · 第 {page} 页</span><button className="button secondary" disabled={loading || page <= 1 || !!error} onClick={() => load(page - 1)}>上一页</button><button className="button secondary" disabled={loading || page * 20 >= total || !!error} onClick={() => load(page + 1)}>下一页</button></div>
    </section></></Localized>;
}

function RootGate() {
  useLanguage();
  const { user, ready, switchingWorkspace } = useAuth();
  const location = useLocation();
  if (!ready) return <Localized><div className="boot">正在验证登录状态…</div></Localized>;
  if (switchingWorkspace) return <Localized><div className="boot">正在更新工作空间权限…</div></Localized>;
  if (!user) {
    if (location.pathname === "/login") return <Localized><LoginPage/></Localized>;
    if (location.pathname === "/register") return <Localized><RegisterPage/></Localized>;
    return <Localized><Navigate to="/login" replace/></Localized>;
  }
  if (location.pathname === "/login" || location.pathname === "/") return <Localized><Navigate to={defaultLanding(user)} replace/></Localized>;
  return <Localized><AppShell key={`${user.tenant_id}/${user.department_id}/${user.application_id}`}/></Localized>;
}

export default function App() {
  useLanguage(); return <Localized><AuthProvider><RootGate/></AuthProvider></Localized>; }
