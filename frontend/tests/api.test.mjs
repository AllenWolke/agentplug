import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, createApiClient, parseSSEChunk, toQuery } from "../src/api.js";
import { applicationCreateCommand } from "../src/features/identity/application-command.js";
import { applicationInstallationCommand } from "../src/features/identity/application-installation-command.js";

test("query omits empty values and preserves filters", () => {
  assert.equal(toQuery({ task_id: "t-1", severity: "", page: 1 }), "?task_id=t-1&page=1");
});

test("browser conversation commands use module routes and rely on server session scope", async () => {
  let request;
  const api = createApiClient({
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify({ code: 0, message: "ok", data: { total: 0, items: [] } }), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  const command = { id: "session-1", kind: "qa", agent_id: "document-assistant", agent_version_id: "v1" };
  await api.createConversationSession(command);
  assert.equal(request.options.method, "POST");
  assert.deepEqual(JSON.parse(request.options.body), command);
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.headers["X-Mock-Tenant"], undefined);
  assert.equal(request.options.headers["X-Api-Key"], undefined);
});

test("auth endpoints do not use the API prefix", async () => {
  let url;
  const api = createApiClient({ fetchImpl: async (value) => { url = value; return new Response(JSON.stringify({ username: "alice" }), { status: 200, headers: { "content-type": "application/json" } }); } });
  await api.login("alice", "secret");
  assert.equal(url, "/auth/login");
});

test("legacy runtime-binding API aliases are absent after Catalog Deployment cutover", () => {
  const api = createApiClient({ fetchImpl: async () => new Response("{}", { status: 200 }) });
  assert.equal(Object.hasOwn(api, "runtimeBinding"), false);
  assert.equal(Object.hasOwn(api, "putRuntimeBinding"), false);
});

test("model and policy assets use modular governance routes", async () => {
  const urls = [];
  const api = createApiClient({ fetchImpl: async (url) => { urls.push(url); return new Response(JSON.stringify({ code: 0, message: "ok", data: [] }), { status: 200, headers: { "content-type": "application/json" } }); } });
  await api.modelProviders({ tenant_id: "tenant-demo", limit: 100 });
  await api.policyAssets({ tenant_id: "tenant-demo" }, "runtime");
  assert.deepEqual(urls, ["/api/modules/model-governance/providers?tenant_id=tenant-demo&limit=100", "/api/modules/policyasset/assets?tenant_id=tenant-demo&type=runtime&limit=100"]);
});

test("identity management reads use the same-origin platform module gateway", async () => {
  const urls = [];
  const api = createApiClient({ fetchImpl: async (url) => {
    urls.push(url);
    return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.tenants();
  await api.departments("tenant-demo");
  await api.applications();
  assert.deepEqual(urls, [
    "/api/modules/identity/tenants?page=1&page_size=100",
    "/api/modules/identity/departments?tenant_id=tenant-demo&page=1&page_size=100",
    "/api/modules/identity/applications?page=1&page_size=100"
  ]);
});

test("Model Provider and immutable Model Version operations use the modular governance route", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.modelProviders({ limit: 100 });
  await api.createModelProvider({ provider_key: "local-qwen", secret_ref: "secret://model/local-qwen" });
  await api.approveModelProvider("provider-a", 1);
  await api.modelDefinitions({ provider_id: "provider-a", limit: 100 });
  await api.createModelDefinition({ provider_id: "provider-a", model_key: "qwen-7b", kind: "chat" });
  await api.modelDefinitionVersions("model-a", { limit: 100 });
  await api.createModelDefinitionVersion("model-a", { semantic_version: "1.0.0" });
  await api.approveModelVersion("model-a", "version-a", 1);
  assert.deepEqual(requests.map((request) => request.url), [
    "/api/modules/model-governance/providers?limit=100",
    "/api/modules/model-governance/providers",
    "/api/modules/model-governance/providers/provider-a/approve",
    "/api/modules/model-governance/models?provider_id=provider-a&limit=100",
    "/api/modules/model-governance/models",
    "/api/modules/model-governance/models/model-a/versions?limit=100",
    "/api/modules/model-governance/models/model-a/versions",
    "/api/modules/model-governance/models/model-a/versions/version-a/approve"
  ]);
  assert.equal(JSON.parse(requests[1].options.body).secret_ref, "secret://model/local-qwen");
  assert.equal(requests.some((request) => request.url.startsWith("/api/v2/")), false);
  assert.equal(requests.every((request) => request.options.credentials === "same-origin"), true);
});

test("six policy assets and snapshot publication use the modular policy control plane", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const scope = { tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a", agent_id: "qa", agent_version_id: "v1" };
  await api.policyAssets(scope, "tool");
  await api.createPolicyAsset({ id: "tool-a", type: "tool", scope, content: { allowed_tools: ["search"] } });
  await api.publishPolicyAsset("tool", "tool-a", { scope, expected_revision: 1 });
  await api.currentPolicySnapshot(scope);
  await api.publishPolicySnapshot({ scope, expected_revision: 0, assets: { tool: { id: "tool-a", revision: 2 } } });
  assert.equal(requests[0].url, "/api/modules/policyasset/assets?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_id=qa&agent_version_id=v1&type=tool&limit=100");
  assert.equal(requests[1].url, "/api/modules/policyasset/assets");
  assert.equal(requests[2].url, "/api/modules/policyasset/assets/tool/tool-a/publish");
  assert.match(requests[3].url, /^\/api\/modules\/policyasset\/snapshots\/current\?/);
  assert.equal(requests[4].url, "/api/modules/policyasset/snapshots/publish");
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
});

test("application directory sends bounded page filters and disables with a revision fence", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [], total: 0, page: 2, page_size: 10 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.applications({ department_id: "dept-a", page: 2, page_size: 10 });
  await api.disableApplication("app-a", "dept-a", 7);
  assert.equal(requests[0].url, "/api/modules/identity/applications?page=2&page_size=10&department_id=dept-a");
  assert.equal(requests[1].url, "/api/modules/identity/applications/app-a/disable?department_id=dept-a");
  assert.equal(requests[1].options.method, "POST");
  assert.deepEqual(JSON.parse(requests[1].options.body), { expected_revision: 7 });
});

test("principal deactivation uses the Identity module and the server-side revision fence", async () => {
  let request;
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    request = { url, options };
    return new Response(JSON.stringify({ id: "alice", is_active: false, revision: 5 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const result = await api.disableIdentityPrincipal("alice / injected", 4);
  assert.equal(request.url, "/api/modules/identity/principals:disable");
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.credentials, "same-origin");
  assert.deepEqual(JSON.parse(request.options.body), { principal_id: "alice / injected", expected_revision: 4 });
  assert.equal(result.revision, 5);
});

test("own password change uses the authenticated Identity gateway without transmitting scope", async () => {
  let request;
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    request = { url, options };
    return new Response(JSON.stringify({ auth_revision: 2, reauthentication_required: true }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const result = await api.changeOwnIdentityPassword("current-password", "new-password-value");
  assert.equal(request.url, "/api/modules/identity/credentials:change-password");
  assert.equal(request.options.method, "POST");
  assert.equal(request.options.credentials, "same-origin");
  assert.deepEqual(JSON.parse(request.options.body), { current_password: "current-password", new_password: "new-password-value" });
  assert.equal(request.options.headers["X-Tenant-ID"], undefined);
  assert.deepEqual(result, { auth_revision: 2, reauthentication_required: true });
});

test("application create command derives scope from the authenticated user, not form fields", () => {
  assert.deepEqual(applicationCreateCommand({ tenant_id: "attacker", department_id: "other", code: " new-app ", name: " New App " }, {
    tenant_id: "tenant-a", department_id: "dept-a"
  }), { tenant_id: "tenant-a", department_id: "dept-a", code: "new-app", name: "New App" });
  assert.throws(() => applicationCreateCommand({ code: "new-app", name: "New App" }, { tenant_id: "tenant-a" }), /租户与部门作用域/);
});

test("application Installation command derives scope from the user and rejects unpublished versions", () => {
  const user = { tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a" };
  const definition = { id: "definition-a", agent_key: "qa-agent", status: "published" };
  const version = { id: "version-a", definition_id: "definition-a", status: "published" };
  assert.deepEqual(applicationInstallationCommand({
    tenant_id: "attacker-tenant", department_id: "other-dept", application_id: "other-app",
    version_id: "client-version", display_name: " QA ", deployment_mode: "managed", drain_policy: "wait"
  }, user, definition, version, "installation-a"), {
    id: "installation-a", tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a",
    agent_id: "qa-agent", version_id: "version-a", display_name: "QA", deployment_mode: "managed",
    drain_policy: "wait", retention_policy_id: "default", status: "provisioning", revision: 1
  });
  assert.throws(() => applicationInstallationCommand({ display_name: "QA" }, user, definition, { ...version, status: "draft" }, "installation-b"), /已发布/);
});

test("identity writes use modular routes and include required resource identity", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ id: "generated-by-test" }), { status: 201, headers: { "content-type": "application/json" } });
  } });
  await api.createTenant({ code: "tenant-new", name: "New tenant" });
  await api.createDepartment({ tenant_id: "tenant-demo", code: "dept-new", name: "New department" });
  await api.createApplication({ tenant_id: "tenant-demo", department_id: "dept-new", code: "app-new", name: "New application" });
  assert.deepEqual(requests.map((request) => request.url), [
    "/api/modules/identity/tenants",
    "/api/modules/identity/departments",
    "/api/modules/identity/applications"
  ]);
  for (const request of requests) {
    const body = JSON.parse(request.options.body);
    assert.ok(body.id);
    assert.equal(body.status, "active");
    assert.equal(body.revision, 1);
    assert.equal(request.options.method, "POST");
  }
});

test("AgentGuard catalog reads use the scoped modular Catalog contract", async () => {
  let requested;
  const api = createApiClient({ fetchImpl: async (url, options) => {
    requested = { url, options };
    return new Response(JSON.stringify({ items: [{ agent_id: "ops-assistant", access_status: "granted" }] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const result = await api.myAgentCatalog();
  assert.equal(requested.url, "/api/modules/catalog/available");
  assert.equal(requested.options.credentials, "same-origin");
  assert.equal(requested.options.headers["X-Tenant-ID"], undefined);
  assert.equal(result.items[0].access_status, "granted");
});

test("existing module clients keep raw platform response contracts", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [], total: 0 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const result = await api.conversations({ page: 1, page_size: 5 });
  assert.deepEqual(result, { items: [], total: 0 });
  assert.equal(requests[0].url, "/api/modules/conversation/sessions?page=1&page_size=5");
  assert.equal(requests[0].options.credentials, "same-origin");
});

test("conversation writes use the platform module boundary", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.createConversationSession({ id: "session-1", kind: "qa", agent_id: "qa-agent", agent_version_id: "v1" });
  await api.appendConversationMessage("session-1", { id: "message-1", role: "user", content: "问题" });
  await api.startConversationRun("session-1", { run_id: "run-1", idempotency_key: "idem-1", agent_endpoint: "http://agent" });
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/conversation/sessions",
    "/api/modules/conversation/sessions/session-1/messages",
    "/api/modules/conversation/sessions/session-1/runs",
  ]);
  assert.deepEqual(requests.map((item) => item.options.method), ["POST", "POST", "POST"]);
  assert.equal(JSON.parse(requests[2].options.body).run_id, "run-1");
});

test("conversation deletion governance uses the scoped modular boundary", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.conversationDeletionRequests({ page: 1, page_size: 25 });
  await api.approveConversationDeletion("delete-1");
  assert.deepEqual(requests.map((request) => request.url), [
    "/api/modules/conversation/deletion-requests?page=1&page_size=25",
    "/api/modules/conversation/deletion-requests/delete-1/approve"
  ]);
  assert.equal(requests[1].options.method, "POST");
});

test("managed conversation search uses the modular conversation boundary", async () => {
  let request;
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    request = { url, options };
    return new Response(JSON.stringify({ items: [{ id: "session-1" }], total: 1, page: 1, page_size: 50 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const result = await api.globalConversationSearch({ kind: "qa", q: "贷款", page: 1, page_size: 50 });
  assert.equal(request.url, "/api/modules/conversation/managed-search?kind=qa&q=%E8%B4%B7%E6%AC%BE&page=1&page_size=50");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.headers["X-Tenant-ID"], undefined);
  assert.equal(result.total, 1);
});

test("Agent Catalog CRUD and lifecycle use only the modular Catalog boundary", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.catalogDefinitions({ limit: 20 });
  await api.catalogCreateDefinition({ id: "definition-1", description: "A definition" });
  await api.catalogDefinitionVersions("definition-1", { limit: 20 });
  await api.catalogCreateVersion("definition-1", { id: "version-1", manifest: { manifest_version: "agent-manifest/v1" } });
  await api.catalogTransitionDefinition("definition-1", "publish", 2);
  await api.catalogTransitionVersion("version-1", "evaluate", 1);
  await api.catalogInstallations({ tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a" });
  await api.catalogRollbackInstallation("install-1", "version-0", 7);
  await api.catalogCreateInstallation({ id: "install-1", deployment_mode: "managed" });
  await api.catalogVersion("version-1");
  await api.catalogDeployments("install-1", { tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a" });
  await api.catalogCreateDeployment("install-1", { desired_revision: 0 });
  await api.catalogObserveDeployment("install-1", "deployment-1", { desired_revision: 1, status: "ready" });
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/catalog/definitions?limit=20",
    "/api/modules/catalog/definitions",
    "/api/modules/catalog/definitions/definition-1/versions?limit=20",
    "/api/modules/catalog/definitions/definition-1/versions",
    "/api/modules/catalog/definitions/definition-1/publish",
    "/api/modules/catalog/versions/version-1/evaluate",
    "/api/modules/catalog/installations?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&limit=100",
    "/api/modules/catalog/installations/install-1/rollback",
    "/api/modules/catalog/installations",
    "/api/modules/catalog/versions/version-1",
    "/api/modules/catalog/installations/install-1/deployments?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&limit=100",
    "/api/modules/catalog/installations/install-1/deployments",
    "/api/modules/catalog/installations/install-1/deployments/deployment-1/observe"
  ]);
  assert.deepEqual(JSON.parse(requests[7].options.body), { version_id: "version-0", expected_revision: 7 });
  assert.equal(requests.some((item) => item.url.startsWith("/api/v2/")), false);
});

test("application-scoped Agent Catalog exposes only published candidates through the module API", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [{ id: "published-version", semantic_version: "1.0.0" }] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const scope = { tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a" };
  await api.catalogAvailableDefinitions(scope);
  await api.catalogAvailableDefinitionVersions("definition-a", scope);
  assert.deepEqual(requests.map((request) => request.url), [
    "/api/modules/catalog/available-definitions?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&limit=100",
    "/api/modules/catalog/available-definitions/definition-a/versions?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&limit=100"
  ]);
  assert.equal(requests.every((request) => request.options.credentials === "same-origin"), true);
  assert.equal(requests.some((request) => request.url.startsWith("/api/v1/") || request.url.startsWith("/api/v2/")), false);
});

test("Identity Grant creation, explanation and revocation use the modular Identity boundary", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ allowed: false, reason: "no_matching_grant" }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const scope = { tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a" };
  await api.identityGrants({ tenant_id: "tenant-a", department_id: "dept-a", application_id: "app-a", agent_instance_id: "install-1", subject_type: "service_principal" });
  await api.identityPrincipals({ tenant_id: "tenant-a", principal_type: "service_principal" });
  await api.createIdentityPrincipal({ type: "service_principal", id: "batch-system", tenant_id: "tenant-a", is_active: true });
  await api.createIdentityGrant({ id: "grant-1", subject_type: "user" });
  await api.identityExplainGrant({ scope: { ...scope, agent_instance_id: "install-1" }, principal_type: "user", principal_id: "alice", action: "run" });
  await api.revokeIdentityGrant("grant-1", { ...scope, agent_instance_id: "install-1" }, 1);
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/identity/grants?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_instance_id=install-1&subject_type=service_principal",
    "/api/modules/identity/principals?tenant_id=tenant-a&principal_type=service_principal",
    "/api/modules/identity/principals",
    "/api/modules/identity/grants",
    "/api/modules/identity/grants:explain",
    "/api/modules/identity/grants/grant-1/revoke?tenant_id=tenant-a&department_id=dept-a&application_id=app-a&agent_instance_id=install-1"
  ]);
  assert.equal(JSON.parse(requests[5].options.body).expected_revision, 1);
});

test("Agent access request lifecycle uses scoped Identity module contracts", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ id: "iar-1", status: "pending", items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.identityAgentAccessRequests({ status: "pending" });
  await api.createIdentityAgentAccessRequest({ agent_instance_id: "install-1", actions: ["run"], reason: "Need access for this work" });
  await api.decideIdentityAgentAccessRequest("iar-1", "approve", { expected_revision: 1, comment: "Approved for duties" });
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/identity/access-requests?status=pending",
    "/api/modules/identity/access-requests",
    "/api/modules/identity/access-requests/iar-1/approve"
  ]);
  assert.equal(JSON.parse(requests[1].options.body).agent_instance_id, "install-1");
  assert.equal(JSON.parse(requests[1].options.body).subject_id, undefined);
  assert.equal(JSON.parse(requests[2].options.body).expected_revision, 1);
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
});

test("self-registration and enrollment review use the Identity module contract", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ registration_id: "reg-1", status: "contact_verification_pending", status_token: "opaque-token", items: [], total: 0, page: 1, page_size: 20 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.registrationAgentCatalog();
  await api.register({ username: "new.user", requested_agent_ids: ["reg-qa"] });
  await api.verifyRegistration("reg-1", "opaque-token", "123456");
  await api.registrationStatus("reg-1", "opaque-token");
  await api.withdrawRegistration("reg-1", "opaque-token", 2);
  await api.userEnrollments({ status: "pending_review", page: 1, page_size: 20 });
  await api.approveEnrollment("reg-1", { expected_revision: 2, comment: "approved", grants: [{ agent_instance_id: "install-qa", actions: ["run"] }] });
  await api.rejectEnrollment("reg-2", { expected_revision: 1, comment: "not approved" });
  assert.deepEqual(requests.map((item) => item.url), [
    "/auth/registration-agent-catalog",
    "/auth/register",
    "/auth/registrations/reg-1/verify-contact",
    "/auth/registrations/reg-1/status",
    "/auth/registrations/reg-1/withdraw",
    "/api/modules/identity/enrollments?status=pending_review&page=1&page_size=20",
    "/api/modules/identity/enrollments/reg-1/approve",
    "/api/modules/identity/enrollments/reg-2/reject"
  ]);
  assert.equal(requests[2].options.headers["X-Registration-Token"], "opaque-token");
  assert.equal(new URL(`http://example.test${requests[2].url}`).searchParams.has("registration_token"), false);
  assert.equal(JSON.parse(requests[6].options.body).grants[0].agent_instance_id, "install-qa");
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
});

test("module error objects become stable ApiError code and message", async () => {
  const api = createApiClient({ fetchImpl: async () => new Response(JSON.stringify({ error: { code: "REVISION_CONFLICT" } }), { status: 409, headers: { "content-type": "application/json" } }) });
  await assert.rejects(api.userEnrollments({}), (error) => error.status === 409 && error.code === "REVISION_CONFLICT" && error.message.includes("REVISION_CONFLICT"));
});

test("machine credential lifecycle uses the modular Identity boundary and revision CAS", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ client_id: "batch-system", status: "active", revision: 2 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.identityMachineCredentials({ tenant_id: "tenant-a" });
  await api.createIdentityMachineCredential({ principal_id: "batch-system", network_cidrs: ["10.1.0.0/16"] });
  await api.rotateIdentityMachineCredential("batch-system", { expected_revision: 1, network_cidrs: ["10.2.0.0/16"] });
  await api.disableIdentityMachineCredential("batch-system", 2);
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/identity/machine-credentials?tenant_id=tenant-a",
    "/api/modules/identity/machine-credentials",
    "/api/modules/identity/machine-credentials/batch-system/rotate",
    "/api/modules/identity/machine-credentials/batch-system/disable"
  ]);
  assert.equal(requests[2].options.method, "POST");
  assert.equal(JSON.parse(requests[2].options.body).expected_revision, 1);
  assert.equal(JSON.parse(requests[3].options.body).expected_revision, 2);
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
});

test("execution task SSE uses the module gateway URL without the legacy API prefix", async () => {
  let requestedURL = "";
  const api = createApiClient({ fetchImpl: async (url) => {
    requestedURL = url;
    return new Response('id: 1\nevent: status\ndata: {"status":"running"}\n\n', { status: 200, headers: { "content-type": "text/event-stream" } });
  } });
  const events = [];
  await api.taskEvents("run-123", (event) => events.push(event));
  assert.equal(requestedURL, "/api/modules/execution/platform/runs/run-123/events");
  assert.equal(events.length, 1);
  assert.equal(events[0].data.status, "running");
});

test("Run reviewer reads a scoped snapshot and submits only a decision", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ run_id: "qa-run", status: "waiting_review" }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.runReviewSnapshot("qa-run");
  await api.decideRunReview("qa-run", "reject", "依据不支持结论");
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/execution/platform/runs/qa-run/review",
    "/api/modules/execution/platform/runs/qa-run/resume"
  ]);
  assert.equal(requests[0].options.method, "GET");
  assert.deepEqual(JSON.parse(requests[1].options.body), { decision: "reject", comment: "依据不支持结论" });
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
});

test("audit search uses the modular audit boundary with caller filters", async () => {
  let request;
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    request = { url, options };
    return new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 100 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.audits({ task_id: "task-1", trace_id: "trace-1", page: 1, page_size: 100 });
  assert.equal(request.url, "/api/modules/audit/events?task_id=task-1&trace_id=trace-1&page=1&page_size=100");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.headers["X-Tenant-ID"], undefined);
});

test("policy assets use the versioned module contract", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => { requests.push({ url, options }); return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } }); } });
  await api.policyAssets({ tenant_id: "tenant-demo", application_id: "app-demo" }, "tool");
  await api.createPolicyAsset({ type: "tool", asset_id: "readonly", policy: { allowed_tools: ["risk.lookup"] } });
  assert.equal(requests[0].url, "/api/modules/policyasset/assets?tenant_id=tenant-demo&application_id=app-demo&type=tool&limit=100");
  assert.equal(requests[1].url, "/api/modules/policyasset/assets");
  assert.equal(requests[1].options.method, "POST");
  assert.equal(JSON.parse(requests[1].options.body).asset_id, "readonly");
});

test("Agent Factory mapping lifecycle uses only the module routes and never accepts caller scope", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [], status: "published", revision: 2 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const spec = { mapping_id: "legacy-qa", version: "1.0.0", kind: "legacy-http", request: { message: "input.question" }, response: { answer: "body.output" } };
  await api.factoryMappings({ limit: 50 });
  await api.createFactoryMapping({ mapping_id: spec.mapping_id, kind: spec.kind, spec });
  await api.factoryMapping("mapping-1");
  await api.dryRunFactoryMapping("mapping-1", { input: { question: "q" }, context: {}, body: { output: "a" } });
  await api.factoryMappingEvidence("mapping-1", { limit: 20 });
  await api.publishFactoryMapping("mapping-1", 1);
  assert.deepEqual(requests.map((item) => item.url), [
    "/api/modules/agent-factory/mappings?limit=50",
    "/api/modules/agent-factory/mappings",
    "/api/modules/agent-factory/mappings/mapping-1",
    "/api/modules/agent-factory/mappings/mapping-1/dry-run",
    "/api/modules/agent-factory/mappings/mapping-1/evidence?limit=20",
    "/api/modules/agent-factory/mappings/mapping-1/publish"
  ]);
  assert.deepEqual(JSON.parse(requests[1].options.body), { mapping_id: spec.mapping_id, kind: spec.kind, spec });
  assert.deepEqual(JSON.parse(requests[5].options.body), { revision: 1 });
  assert.equal(requests.every((item) => item.options.credentials === "same-origin"), true);
  assert.equal(requests.every((item) => item.options.headers["X-Tenant-ID"] === undefined && item.options.headers["X-Application-ID"] === undefined), true);
  assert.equal(requests.slice(1).every((item) => !JSON.stringify(item.options.body || "").includes("tenant_id")), true);
});

test("evaluation product UI operations use the module DTOs, CAS revisions, and session identity boundary", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [], total: 0, page: 1, page_size: 50 }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.evaluationProductDatasets({ page: 1, page_size: 50 });
  await api.evaluationProductSuites({ page: 1, page_size: 50 });
  await api.evaluationProductMetrics({ page: 1, page_size: 50 });
  await api.evaluationProductRuns({ page: 1, page_size: 50 });
  await api.evaluationProductEvidence({ page: 1, page_size: 50 });
  await api.evaluationProductReviews({ page: 1, page_size: 50 });
  await api.evaluationProductBaselines({ page: 1, page_size: 50 });
  await api.createEvaluationProductDataset({ name: "gold", version: "1.0.0", source_type: "manual_gold", cases: [{ case_id: "c-1" }] });
  await api.reviewEvaluationProductDataset("dataset-1", { expected_revision: 3, decision: "approved", reason: "verified" });
  await api.publishEvaluationProductDataset("dataset-1", { expected_revision: 4 });
  await api.createEvaluationProductMetric({ metric_id: "citation", version: "1.0.0", name: "Citation Accuracy", kind: "citation_accuracy", formula: { field: "citations" } });
  await api.publishEvaluationProductMetric("citation.1.0.0", { expected_revision: 1 });
  await api.createEvaluationProductSuite({ name: "qa-suite", version: "1.0.0", dataset_id: "dataset-1", agent_id: "qa", agent_version_id: "qa-v1", metric_ids: ["citation.1.0.0"] });
  await api.createEvaluationProductRun({ suite_id: "suite-1", idempotency_key: "run-request-1" });
  await api.cancelEvaluationProductRun("run-1", { expected_revision: 2 });
  await api.createEvaluationProductReview({ evidence_id: "evidence-1", decision: "approved", reason: "reviewed" });
  await api.createEvaluationProductBaseline({ suite_id: "suite-1", evidence_id: "evidence-1", expected_revision: 0 });
  await api.evaluateEvaluationProductGate({ evidence_id: "evidence-1", minimum_score: 0.8 });

  assert.deepEqual(requests.map(({ url }) => url), [
    "/api/modules/evaluation-product/datasets?page=1&page_size=50",
    "/api/modules/evaluation-product/suites?page=1&page_size=50",
    "/api/modules/evaluation-product/metrics?page=1&page_size=50",
    "/api/modules/evaluation-product/runs?page=1&page_size=50",
    "/api/modules/evaluation-product/evidence?page=1&page_size=50",
    "/api/modules/evaluation-product/reviews?page=1&page_size=50",
    "/api/modules/evaluation-product/baselines?page=1&page_size=50",
    "/api/modules/evaluation-product/datasets",
    "/api/modules/evaluation-product/datasets/dataset-1/review",
    "/api/modules/evaluation-product/datasets/dataset-1/publish",
    "/api/modules/evaluation-product/metrics",
    "/api/modules/evaluation-product/metrics/citation.1.0.0/publish",
    "/api/modules/evaluation-product/suites",
    "/api/modules/evaluation-product/runs",
    "/api/modules/evaluation-product/runs/run-1/cancel",
    "/api/modules/evaluation-product/reviews",
    "/api/modules/evaluation-product/baselines",
    "/api/modules/evaluation-product/gates/evaluate"
  ]);
  const bodyAt = (index) => JSON.parse(requests[index].options.body);
  assert.deepEqual(bodyAt(7), { name: "gold", version: "1.0.0", source_type: "manual_gold", cases: [{ case_id: "c-1" }] });
  assert.deepEqual(bodyAt(8), { expected_revision: 3, decision: "approved", reason: "verified" });
  assert.deepEqual(bodyAt(9), { expected_revision: 4 });
  assert.deepEqual(bodyAt(10), { metric_id: "citation", version: "1.0.0", name: "Citation Accuracy", kind: "citation_accuracy", formula: { field: "citations" } });
  assert.deepEqual(bodyAt(12), { name: "qa-suite", version: "1.0.0", dataset_id: "dataset-1", agent_id: "qa", agent_version_id: "qa-v1", metric_ids: ["citation.1.0.0"] });
  assert.deepEqual(bodyAt(13), { suite_id: "suite-1", idempotency_key: "run-request-1" });
  assert.deepEqual(bodyAt(14), { expected_revision: 2 });
  assert.deepEqual(bodyAt(15), { evidence_id: "evidence-1", decision: "approved", reason: "reviewed" });
  assert.deepEqual(bodyAt(16), { suite_id: "suite-1", evidence_id: "evidence-1", expected_revision: 0 });
  assert.deepEqual(bodyAt(17), { evidence_id: "evidence-1", minimum_score: 0.8 });
  assert.equal(requests.every(({ options }) => options.credentials === "same-origin"), true);
  assert.equal(requests.some(({ options }) => options.headers["X-Tenant-ID"] || options.headers["X-Principal-ID"]), false);
});

test("evaluation product availability uses the authenticated module endpoint", async () => {
  let request;
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    request = { url, options };
    return new Response(JSON.stringify({ configured: false, state: "unavailable", reason_code: "EVALUATOR_UNAVAILABLE" }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const availability = await api.evaluationProductAvailability();
  assert.equal(request.url, "/api/modules/evaluation-product/availability");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.headers["X-Tenant-ID"], undefined);
  assert.deepEqual(availability, { configured: false, state: "unavailable", reason_code: "EVALUATOR_UNAVAILABLE" });
});

test("Model Deployment and Access Policy calls target module routes directly", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  await api.modelDeployments({ limit: 50 });
  await api.modelPolicies({ limit: 50 });
  await api.approveModelPolicy("policy-a", 3);
  await api.revokeModelPolicy("policy-a", 4);
  assert.deepEqual(requests.map(({ url }) => url), [
    "/api/modules/model-governance/deployments?limit=50",
    "/api/modules/model-governance/access-policies?limit=50",
    "/api/modules/model-governance/access-policies/policy-a/approve",
    "/api/modules/model-governance/access-policies/policy-a/revoke"
  ]);
  assert.equal(requests.every(({ options }) => options.credentials === "same-origin"), true);
  assert.deepEqual(JSON.parse(requests[2].options.body), { revision: 3 });
  assert.deepEqual(JSON.parse(requests[3].options.body), { revision: 4 });
});

test("model price catalog uses module routes and approval revision", async () => {
  const requests = [];
  const api = createApiClient({ fetchImpl: async (url, options = {}) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const price = { model_version_id: "version-1", currency: "CNY", input_micros_per_1k_tokens: 3, output_micros_per_1k_tokens: 7, effective_from: "2026-09-25T00:00:00.000Z" };
  await api.modelPrices({ limit: 100 });
  await api.createModelPrice(price);
  await api.approveModelPrice("price-1", 2);
  assert.deepEqual(requests.map(({ url }) => url), [
    "/api/modules/model-governance/prices?limit=100",
    "/api/modules/model-governance/prices",
    "/api/modules/model-governance/prices/price-1/approve"
  ]);
  assert.equal(requests.every(({ options }) => options.credentials === "same-origin"), true);
  assert.deepEqual(JSON.parse(requests[1].options.body), price);
  assert.deepEqual(JSON.parse(requests[2].options.body), { revision: 2 });
});

test("retired v1 admin aliases cannot be called from the browser client", () => {
  const api = createApiClient({ fetchImpl: async () => new Response("{}", { status: 200 }) });
  for (const name of [
    "batches", "runCheck", "ask", "qaRecords", "agents", "publishedAgents",
    "grantUserEntitlement", "revokeUserEntitlement", "agentVersions", "createAgent",
    "createAgentVersion", "publishAgentVersion", "rollbackAgent", "agentRelease",
    "agentReleaseMetrics", "rollbackCurrentRelease", "updateReleaseRollout",
    "modelProfiles", "modelCatalog", "createModelProfile", "putModelPrice",
    "createModelPriceVersion", "putBudget", "budgetAlerts", "prompts", "promptVersions",
    "createPrompt", "createPromptVersion", "promotePromptVersion", "memoryPolicies",
    "createMemoryPolicy", "tools", "toolPolicies", "createToolPolicy", "knowledgePolicies",
    "createKnowledgePolicy", "runtimePolicies", "createRuntimePolicy", "agentTemplates",
    "createAgentTemplate", "agentTemplate", "agentMappings", "createAgentMapping",
    "agentMapping", "dryRunAgentMapping", "publishAgentMapping"
  ]) {
    assert.equal(Object.hasOwn(api, name), false, `legacy API alias ${name} must be retired`);
  }
});

test("system operations loads scoped durable usage runs and their metered steps", async () => {
  let requested;
  const api = createApiClient({ fetchImpl: async (url) => { requested = url; return new Response(JSON.stringify({ items: [] }), { status: 200, headers: { "content-type": "application/json" } }); } });
  const range = { from: "2026-09-01T00:00:00Z", to: "2026-09-07T00:00:00Z" };
  await api.usageRuns({ ...range, page: 2, page_size: 20 });
  assert.equal(requested, "/api/modules/usage/usage/runs?from=2026-09-01T00%3A00%3A00Z&to=2026-09-07T00%3A00%3A00Z&page=2&page_size=20");
  await api.usageRunSteps("run-a", range);
  assert.equal(requested, "/api/modules/usage/usage/runs/run-a/steps?from=2026-09-01T00%3A00%3A00Z&to=2026-09-07T00%3A00%3A00Z");
});

test("backend error becomes ApiError with code and trace", async () => {
  const api = createApiClient({ fetchImpl: async () => new Response(JSON.stringify({ code: 40301, message: "forbidden", trace_id: "trace-x" }), { status: 403, headers: { "content-type": "application/json" } }) });
  await assert.rejects(() => api.createConversationSession({ id: "session-1" }), (error) => error instanceof ApiError && error.code === "40301" && error.traceId === "trace-x");
});

test("SSE parser supports partial buffers and JSON payload", () => {
  const first = parseSSEChunk('id: 1\nevent: task_started\ndata: {"stage":"run"}\n\nid: 2\nevent: task_');
  assert.deepEqual(first.events[0], { id: "1", type: "task_started", data: { stage: "run" } });
  const second = parseSSEChunk(first.remainder + 'completed\ndata: {"ok":true}\n\n');
  assert.equal(second.events[0].type, "task_completed");
  assert.equal(second.events[0].data.ok, true);
});
