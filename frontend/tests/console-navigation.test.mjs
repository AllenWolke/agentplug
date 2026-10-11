import test from "node:test";
import assert from "node:assert/strict";
import { agentDisplayName, agentWorkspacePath, agentPresentation } from "../src/features/agent-workspace/catalog-presentation.js";
import { permissionRequestScopes, workspaceDisplayIdentity } from "../src/features/identity/workspace-state.js";
import { canDevelopAgents, canManageCatalog, canConfigureModels, visibleApplications } from "../src/config.js";
import { loadAgentAccessReview } from "../src/features/identity/access-admin-loader.js";

test("Catalog entries without entry_path still route to their exact Agent", () => {
  assert.equal(agentWorkspacePath({ agent_id: "example-go-operations" }), "/workspace/agent/example-go-operations");
  assert.equal(agentWorkspacePath({ agent_id: "x/y?#", entry_path: "https://untrusted.invalid" }), "/workspace/agent/x%2Fy%3F%23");
});

test("batch receipts replace known demo keys with readable names without rewriting custom business names", () => {
  assert.equal(agentDisplayName("example-go-operations"), "Go 运维诊断助手");
  assert.equal(agentDisplayName("example-python-documents"), "Python 文档问答助手");
  assert.equal(agentDisplayName("example-java-tickets"), "Java 工单助手");
  assert.equal(agentDisplayName("Customer Support"), "Customer Support");
});

test("department-only members can request in server-reviewed application scopes without submitting display metadata", () => {
  const department = { scope_type: "department", tenant_id: "t", department_id: "d" };
  const app = { scope_type: "application", tenant_id: "t", department_id: "d", application_id: "a", workspace_name: "Company", management_actions: ["administrator.appoint"] };
  const response = { items: [department], application_workspaces: [app, app, { ...app, tenant_id: "other" }, { ...app, department_id: "" }] };
  assert.deepEqual(permissionRequestScopes(response, "t"), [department, { scope_type: "application", tenant_id: "t", department_id: "d", application_id: "a" }]);
});

test("application card opens the application instead of linking back to its home page", () => {
  assert.equal(visibleApplications({ application_id: "app", department_id: "dept", policy_mode: "v2", capabilities: [] })[0].path, "/workspace/application");
});

test("example inputs match their different public business protocols", () => {
  for (const [id, required] of [["example-go-operations", ["service", "symptom"]], ["example-python-documents", ["question"]], ["example-java-tickets", ["ticket_id", "summary"]]]) {
    const input = JSON.parse(agentPresentation({ agent_id: id }).exampleInput);
    for (const key of required) assert.equal(typeof input[key], "string");
    for (const key of ["notify_me", "sandbox_check", "collaborate"]) assert.notEqual(input[key], true);
  }
  assert.equal(agentPresentation({ agent_id: "custom", name: "Custom Agent" }).exampleInput, "");
});

test("monitoring authority does not expose developer or catalog commands", () => {
  const actor = { policy_mode: "v2", roles: ["admin"], capabilities: ["platform.monitor"] };
  assert.equal(canDevelopAgents(actor), false);
  assert.equal(canManageCatalog(actor), false);
  assert.equal(canConfigureModels(actor), false);
  actor.capabilities = ["agent.develop"];
  assert.equal(canDevelopAgents(actor), true);
  assert.equal(canManageCatalog(actor), false);
  actor.capabilities = ["catalog.manage", "model.configure"];
  assert.equal(canManageCatalog(actor), false);
  assert.equal(canConfigureModels(actor), true);
  assert.equal(canDevelopAgents(actor), false);
  actor.global_capabilities = ["catalog.manage"];
  assert.equal(canManageCatalog(actor), true);
  actor.global_capabilities = [];
  assert.equal(canManageCatalog(actor), false);
});

test("workspace labels do not change identity or take names from another scope", () => {
  const identity = { username: "user", tenant_id: "t", department_id: "d", application_id: "a", capabilities: [] };
  const workspaces = [{ tenant_id: "other", department_id: "d", application_id: "a", application_name: "Wrong" }, { tenant_id: "t", department_id: "d", application_id: "a", application_name: "Application", department_name: "Department", capabilities: ["platform.monitor"] }];
  assert.deepEqual(workspaceDisplayIdentity(identity, workspaces), { ...identity, application_name: "Application", department_name: "Department" });
  assert.equal(workspaceDisplayIdentity(identity, workspaces.slice(0, 1)), identity);
});

test("versioned enrollment page never calls the retired access-request endpoint", async () => {
  const api = { myAgentCatalog: async () => [{ agent_id: "example" }], identityAgentAccessRequests: async () => { throw new Error("Retired route must not be requested"); } };
  assert.deepEqual(await loadAgentAccessReview(api, "v2"), { catalog: [{ agent_id: "example" }], accessRequests: [] });
});
