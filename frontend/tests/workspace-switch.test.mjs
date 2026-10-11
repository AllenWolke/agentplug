import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient } from "../src/api.js";
import { projectSessionIdentity } from "../src/features/identity/workspace-state.js";
const response = (status, body = {}, headers = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("permission projection wins over an identity read preceding another tab's switch", () => {
 const identity = { username: "alice", tenant_id: "t", department_id: "old", application_id: "a", department_name: "Old department" };
 const projection = { policy_mode: "v2", scope: { scope_type: "application", tenant_id: "t", department_id: "new", application_id: "b" }, capabilities: [] };
 const next = projectSessionIdentity(identity, projection);
 assert.equal(next.application_id, "b"); assert.equal(next.department_id, "new"); assert.notEqual(next.department_name, identity.department_name);
 assert.throws(() => projectSessionIdentity(identity, { ...projection, scope: { ...projection.scope, tenant_id: "foreign" } }));
 assert.throws(() => projectSessionIdentity(identity, { policy_mode: "v2" }));
});

test("workspace switching shares the refresh lock and selects the server workspace once", async () => {
 const calls = [], lockNames = [];
 const target = { tenant_id: "t", department_id: "d", application_id: "b" };
 let refreshed = false;
 const client = createApiClient({ refreshLocks: { request: async (name, callback) => { lockNames.push(name); return callback(); } }, fetchImpl: async (url, options) => {
  calls.push({ url, options });
  if (url === "/auth/me") return response(401, {}, { "X-Authentication-Error": "access_token_invalid" });
  if (url === "/auth/refresh") { refreshed = true; return response(200); }
  assert.equal(url, "/auth/workspace"); assert.equal(refreshed, true);
  assert.deepEqual(JSON.parse(options.body), target);
  return response(200, { username: "alice", ...target });
 } });
 const result = await client.switchWorkspace(target);
 assert.equal(result.application_id, "b");
 assert.deepEqual(lockNames, ["agentplug-auth-refresh"]);
 assert.deepEqual(calls.map(value => value.url), ["/auth/me", "/auth/refresh", "/auth/workspace"]);
});

test("workspace membership denial is never retried and does not rotate authentication", async () => {
 const calls = [];
 const client = createApiClient({ fetchImpl: async url => { calls.push(url); return url === "/auth/me" ? response(200) : response(403, { message: "not a member" }); } });
 await assert.rejects(client.switchWorkspace({ tenant_id: "t", department_id: "d", application_id: "b" }), error => error.status === 403);
 assert.deepEqual(calls, ["/auth/me", "/auth/workspace"]);
});
