import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/App.jsx", import.meta.url), "utf8");
const governancePanel = source.match(/function ApplicationGovernancePanel\([\s\S]*?(?=\nfunction IntegrationAdmin\()/)?.[0] || "";
const apiSource = await readFile(new URL("../src/api.js", import.meta.url), "utf8");
const accessAdminLoaderSource = await readFile(new URL("../src/features/identity/access-admin-loader.js", import.meta.url), "utf8");
const agentCatalogSource = await readFile(new URL("../src/features/agent-catalog/AgentCatalog.jsx", import.meta.url), "utf8");
const workspaceSource = await readFile(new URL("../src/features/agent-workspace/AgentWorkspace.jsx", import.meta.url), "utf8");
const applicationInstallationsSource = await readFile(new URL("../src/features/agent-catalog/ApplicationAgentInstallations.jsx", import.meta.url), "utf8");
const departmentAdminSource = await readFile(new URL("../src/features/identity/DepartmentAdmin.jsx", import.meta.url), "utf8");

test("React entry implements login and the generic Agent workspace", () => {
  assert.match(source, /登录智能体中台/);
  assert.match(source, /<AgentWorkspace agentId=/);
});

test("administrator workspaces remain present and Agent governance links to modular pages", () => {
  assert.match(source, /系统运维中心/);
  assert.match(source, /平台管理中心/);
  assert.match(source, /id="create-tenant-form"/);
  assert.match(source, /<Route path="\/platform\/departments" element=\{<Guard when=\{\["platform", "company"\].includes\(administrationKind\(user\)\) && user.capabilities\?\.includes\("organization.manage"\)\}>/);
  assert.match(departmentAdminSource, /aria-label="创建公司部门"/);
  assert.doesNotMatch(source, /id="create-department-form"/);
  assert.match(source, /应用与 Agent 管理/);
  assert.match(source, /外部系统接入/);
  assert.match(source, /<ApplicationGovernancePanel user=\{user\}\/?>/);
  for (const [route, label] of [["\/platform\/agent-catalog", "Agent 目录、版本发布与部署"], ["\/platform\/model-governance", "模型与 Provider 治理"], ["\/admin\/policy-assets", "六类应用策略资产"], ["\/platform\/agent-factory", "Agent 模板工厂"], ["\/platform\/adapter-mappings", "Adapter 映射"], ["\/platform\/evaluations", "Agent 评测工作台"]]) {
    assert.ok(governancePanel, "application governance module hub should exist");
    assert.match(governancePanel, new RegExp(route));
    assert.ok(governancePanel.includes(label));
  }
  assert.match(governancePanel, /isPlatformAdmin\(user\)/);
  assert.match(governancePanel, /当前身份不能进入对应管理模块/);
  assert.match(source, /<Route path="\/platform\/agent-catalog" element=\{<Guard when=\{canManageCatalog\(user\)\}>/);
  assert.match(source, /<Route path="\/platform\/model-governance" element=\{<Guard when=\{canConfigureModels\(user\)\}>/);
  assert.match(source, /<Route path="\/platform\/agent-factory" element=\{<Guard when=\{canDevelopAgents\(user\)\}>/);
  assert.match(source, /<Route path="\/platform\/adapter-mappings" element=\{<Guard when=\{canDevelopAgents\(user\)\}>/);
  assert.match(source, /<Route path="\/platform\/evaluations" element=\{<Guard when=\{canUseEvaluationWorkspace\(user\)\}>/);
  assert.match(source, /<Route path="\/admin\/policy-assets" element=\{<Guard when=\{canManagePolicyAssets\(user\)\}>/);
});

test("application Agent governance panel does not call retired mixed-panel APIs", () => {
  assert.ok(governancePanel, "application governance module hub should be extracted from App.jsx");
  for (const legacyCall of ["api.agents(", "api.modelProfiles(", "api.modelCatalog(", "api.prompts(", "api.promptVersions(", "api.tools(", "api.toolPolicies(", "api.memoryPolicies(", "api.knowledgePolicies(", "api.runtimePolicies(", "/platform/v1", "/api/v2/platform"]) {
    assert.equal(governancePanel.includes(legacyCall), false, `legacy call must not remain active: ${legacyCall}`);
  }
  for (const legacyForm of ["create-agent-form", "create-model-profile-form", "create-tool-policy-form", "create-agent-version-form", "publish-agent-version-form", "rollback-agent-form"]) {
    assert.equal(governancePanel.includes(legacyForm), false, `retired mixed-panel form must be removed: ${legacyForm}`);
  }
  assert.match(governancePanel, /Agent Definition、不可变 Version、评测发布/);
  assert.match(governancePanel, /Model、Prompt、Tool、Memory、Knowledge、Runtime/);
  assert.match(governancePanel, /Definition、Version 发布及 Deployment 期望状态由平台管理员/);
});

test("external integration covers all public Agent Run operations", () => {
  assert.match(source, /title="外部系统接入"/);
  assert.match(source, /api\.catalogInstallations\(/);
  assert.match(source, /api\.identityPrincipals\(/);
  assert.match(source, /api\.createIdentityPrincipal\(/);
  assert.match(source, /api\.createIdentityGrant\(/);
  assert.match(source, /api\.revokeIdentityGrant\(/);
  assert.match(source, /api\.identityExplainGrant\(/);
  assert.match(source, /平台管理员在“机器身份凭证”页签发一次性 Secret/);
  assert.doesNotMatch(source, /api\.v2(?:Installations|ExternalClients|CreateExternalClient|RotateExternalClient|DisableExternalClient)/);
  assert.doesNotMatch(source, /\/api\/v2\/oauth\/token/);
  assert.doesNotMatch(apiSource, /X-Client-Secret/);
});

test("machine identity management uses the modular Catalog and Identity contracts only", () => {
  assert.match(source, /稳定主体 ID/);
  assert.match(source, /保存最小权限 Grant/);
  assert.match(source, /租户、应用、Agent Installation 和动作授予最小权限/);
  assert.match(apiSource, /identityPrincipals:.*requestPlatformModule\("identity",\s*"\/principals"/);
  assert.match(apiSource, /createIdentityPrincipal:.*requestPlatformModule\("identity",\s*"\/principals"/);
  assert.match(apiSource, /catalogInstallations:.*requestPlatformModule\("catalog",\s*"\/installations"/);
  assert.doesNotMatch(apiSource, /v2(?:AgentDefinitions|Installations|ExternalClients|CreateGrant|InvokeInstallation)/);
});

test("modular feature clients do not translate retired product routes at runtime", () => {
  assert.doesNotMatch(apiSource, /requestProduct\(/);
  assert.match(apiSource, /factoryMappings:.*requestPlatformModule\("agent-factory",\s*"\/mappings"/s);
  assert.match(apiSource, /modelDeployments:.*requestPlatformModule\("model-governance",\s*"\/deployments"/s);
  assert.match(apiSource, /modelPolicies:.*requestPlatformModule\("model-governance",\s*"\/access-policies"/s);
});

test("React routing guards application and administrator pages", () => {
  assert.match(source, /<Route path="\/workspace\/agent\/:agentId"/);
  assert.match(source, /isSystemAdmin\(user\)/);
  assert.match(source, /isPlatformAdmin\(user\)/);
  assert.match(source, /isIntegrationAdmin\(user\)/);
});

test("application-scoped Agent Catalog drives business navigation and management selectors", () => {
  assert.doesNotMatch(apiSource, /publishedAgents|\/platform\/published-agent-catalog/);
  assert.match(apiSource, /myAgentCatalog:.*requestPlatformModule\("catalog",\s*"\/available"\)/);
  assert.match(source, /api\.myAgentCatalog\(\)/);
  assert.match(source, /name="sidebar_agent_view"/);
  assert.match(agentCatalogSource, /注册 Agent Definition/);
  assert.match(agentCatalogSource, /创建完整不可变 Version/);
  assert.match(agentCatalogSource, /Version 评测与发布/);
  assert.match(source, /agent-catalog-changed/);
  assert.match(source, /agentCatalog\.refresh\(\)/);
  assert.match(source, /agent-catalog-changed/);
  for (const field of ["agent_key", "display_name", "description", "artifact_digest", "manifest"]) assert.match(agentCatalogSource, new RegExp(`name="${field}"`));
});

test("Catalog installation activation is gated by the latest exact-version observed-ready deployment", () => {
  assert.match(agentCatalogSource, /api\.catalogCreateDeployment\(/);
  assert.match(agentCatalogSource, /api\.catalogVersion\(selectedInstallVersionID\)/);
  assert.match(agentCatalogSource, /observed_revision === latest\.desired_revision/);
  assert.match(agentCatalogSource, /disabled=\{!ready\}/);
  assert.match(applicationInstallationsSource, /api\.catalogDeployments\(item\.id, scope\)/);
  assert.match(applicationInstallationsSource, /observed_revision === latestDeployment\.desired_revision/);
  assert.match(applicationInstallationsSource, /disabled=\{!deploymentReady\}/);
  assert.match(applicationInstallationsSource, /等待平台管理员创建当前版本的 Deployment/);
});

test("application admins can request rollback only to a published version of their installed Agent", () => {
  assert.match(applicationInstallationsSource, /publishedRollbackOptions\(asItems\(result\), installation\.version_id\)/);
  assert.match(applicationInstallationsSource, /api\.catalogRollbackInstallation\(installation\.id, target\.id, installation\.revision\)/);
  assert.match(applicationInstallationsSource, /\["active", "suspended"\]\.includes\(installation\.status\)/);
  assert.match(applicationInstallationsSource, /expected_revision|installation\.revision/);
  assert.match(applicationInstallationsSource, /创建目标版本的 Deployment 并完成 Ready 观测/);
});

test("background Agent catalog refresh keeps the active conversation mounted", () => {
  assert.match(source, /const refresh = \(\) => agentCatalog\.refresh\(\)/);
  assert.doesNotMatch(source, /const refresh = \(\) => agentCatalog\.reload\(\)/);
  assert.match(source, /setInterval\(refresh, 15000\)/);
  assert.match(source, /initialized: agentCatalog\.data !== null/);
  assert.match(source, /catalog\.loading && !catalog\.initialized/);
});

test("registration, entitlement guards and durable history are wired to backend APIs", () => {
  for (const token of ["/register", "UserAccessAdmin", "AgentGuard", "您暂无权限使用该agent", "ConversationGovernance"]) assert.match(source, new RegExp(token));
  for (const token of ["/api/modules/", "/enrollments", "/exports", "/deletion-requests"]) assert.match(apiSource, new RegExp(token));
  assert.doesNotMatch(apiSource, /\/admin\/user-enrollments/);
});

test("Agent access requests use Identity module and exact Catalog installation IDs", () => {
  assert.match(apiSource, /identityAgentAccessRequests:.*requestPlatformModule\("identity",\s*"\/access-requests"/);
  assert.match(apiSource, /createIdentityAgentAccessRequest:.*requestPlatformModule\("identity",\s*"\/access-requests"/);
  assert.match(apiSource, /decideIdentityAgentAccessRequest:.*\/access-requests\/\$\{encodeURIComponent\(id\)\}/);
  assert.match(source, /agent_instance_id:installation\.installation_id/);
  assert.match(source, /loadAgentAccessReview, loadEnrollmentReview/);
  assert.match(accessAdminLoaderSource, /api\.identityAgentAccessRequests\(\{ status: "pending" \}\)/);
  const identityLoader = accessAdminLoaderSource.match(/export async function loadAgentAccessReview\([\s\S]*?\n\}/)?.[0] || "";
  assert.doesNotMatch(identityLoader, /userEnrollments/);
  for (const legacy of ["myAgentAccessRequests", "requestAgentAccess", "userAgentAccessRequests", "approveAgentAccessRequest", "rejectAgentAccessRequest"]) {
    assert.doesNotMatch(apiSource, new RegExp(`${legacy}:`));
    assert.doesNotMatch(source, new RegExp(`api\\.${legacy}\\(`));
  }
});

test("generic workspace submits through platform conversation and run boundaries", () => {
  for (const token of ["api.createConversationSession", "api.appendConversationMessage", "api.startConversationRun", "api.taskEvents", "message_id"]) assert.ok(workspaceSource.includes(token));
  assert.match(workspaceSource, /const agent = catalog\.find\(\(item\) => item\.agent_id === agentId\);/);
  assert.match(workspaceSource, /const selectedAgent = agent;/);
  assert.match(workspaceSource, /createConversationSession\(\{[^}]*agent_id: selectedAgent\.agent_id,[^}]*agent_version_id: selectedAgent\.version_id/);
  assert.match(workspaceSource, /agentVersionID: selectedAgent\.version_id,[\s\S]*installationID: selectedAgent\.installation_id/);
  assert.match(workspaceSource, /agent\?\.installation_id/);
});
