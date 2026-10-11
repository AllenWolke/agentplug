import test from "node:test";
import assert from "node:assert/strict";
import { departmentAgentCommand, replaceDepartmentAgentEntry, departmentAgentPolicyDifferences, DAILY_AGENT_ACTIONS } from "../src/features/identity/department-agent-policy.js";
import { delegatedAgentTargets } from "../src/features/identity/organization-access.js";
import { createApiClient } from "../src/api.js";

test("editing a visible Agent preserves other pages, applications and advanced actions", () => {
  const original = [{ application_id: "app", installation_id: "first", actions: ["run", "history.export"], action_versions: { run: 3 } },
    { application_id: "app", installation_id: "page-2", actions: ["run"], expires_at: "2030-01-01T00:00:00Z" },
    { application_id: "other", installation_id: "other-agent", actions: ["history.share"] }];
  const result = replaceDepartmentAgentEntry(original, "app", "first", current => ({ ...current, actions: [...current.actions, "discover"] }));
  assert.deepEqual(result.find(item => item.installation_id === "first").actions, ["discover", "history.export", "run"]);
  assert.deepEqual(result.find(item => item.installation_id === "page-2"), original[1]);
  assert.deepEqual(result.find(item => item.installation_id === "other-agent"), original[2]);
  assert.equal(original[0].actions.length, 2);
  assert.equal(result.some(item => Object.hasOwn(item, "action_versions")), false);
  assert.equal(replaceDepartmentAgentEntry(result, "app", "first", () => null).length, 2);
});

test("department commands use the loaded scope and an explicit legacy migration", () => {
  const policy = { tenant_id: "company", department_id: "sales", revision: 0 };
  const input = { state: { can_manage: true, managed: false, policy }, tenant: "company", department: "sales", entries: [], reason: " reviewed migration ", key: "fixed" };
  const command = departmentAgentCommand(input);
  assert.equal(command.migrate_existing, true);
  assert.equal(command.reason, "reviewed migration");
  assert.throws(() => departmentAgentCommand({ ...input, department: "outside" }));
  assert.throws(() => departmentAgentCommand({ ...input, state: { ...input.state, can_manage: false } }));
  assert.throws(() => departmentAgentCommand({ ...input, entries: [{ actions: [] }] }));
  assert.equal(DAILY_AGENT_ACTIONS.includes("history.export"), false);
  assert.equal(DAILY_AGENT_ACTIONS.includes("model.generate"), true);
});

test("impact preview distinguishes actual action changes from server source generations", () => {
  const before = { entries: [{ application_id: "app", installation_id: "keep", actions: ["run", "discover"], action_versions: { run: 1 } }, { application_id: "other", installation_id: "remove", actions: ["run"] }] };
  const after = { entries: [{ application_id: "app", installation_id: "keep", actions: ["discover", "run"], action_versions: { run: 2 } }, { application_id: "app", installation_id: "add", actions: ["run"] }] };
  const differences = departmentAgentPolicyDifferences(before, after);
  assert.deepEqual(differences.map(item => item.kind).sort(), ["added", "removed"]);
  after.entries[0].actions.push("history.export");
  assert.equal(departmentAgentPolicyDifferences(before, after).filter(item => item.kind === "changed").length, 1);
});

test("a managed department picker cannot fall back to an obsolete wider delegation", () => {
  const scope = { tenant_id: "company", department_id: "sales", application_id: "app" };
  const targets = [{ id: "approved" }, { id: "withdrawn" }];
  const user = { administration_kind: "department", policy_mode: "v2", delegations: [{ status: "active", scope, management_actions: ["authorization.change"], resources: ["withdrawn"] }],
    department_agent_policy: { managed: true, policy: { ...scope, entries: [{ application_id: "app", installation_id: "approved", actions: ["run"] }] } } };
  assert.deepEqual(delegatedAgentTargets(user, targets, scope), [targets[0]]);
  user.department_agent_policy.policy.entries = [];
  assert.deepEqual(delegatedAgentTargets(user, targets, scope), []);
  user.department_agent_policy.policy.entries = [{ application_id: "app", installation_id: "approved", actions: ["run"], expires_at: "2000-01-01" }];
  assert.deepEqual(delegatedAgentTargets(user, targets, scope), []);
  user.department_agent_policy.policy.entries = [{ application_id: "app", installation_id: "approved", actions: ["run"], starts_at: "2099-01-01" }];
  assert.deepEqual(delegatedAgentTargets(user, targets, scope), [targets[0]]);
});

test("uncertain-submit recovery is a scoped read and Agent pages preserve the cursor", async () => {
  const requests = [];
  const client = createApiClient({ fetchImpl: async (url, options) => { requests.push({ url, options }); return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); } });
  await client.departmentAgentChangeReceipt("original-key");
  await client.identityInstallationTargets({ tenant_id: "company", department_id: "sales", application_id: "app" }, "delegation", "agent-100");
  assert.equal(requests[0].url, "/api/modules/identity/department-agent-changes/original-key");
  assert.equal(requests[0].options.method, "GET");
  assert.match(requests[1].url, /after_id=agent-100/);
});
