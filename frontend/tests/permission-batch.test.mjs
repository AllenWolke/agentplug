import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient } from "../src/api.js";
import { agentUseBatchCommand, basicRequestedItems, batchCounts, batchStorageKey, commonRequestScope, continueBatchSteps, decisionBatchCommand, departmentBatchCommand, duplicateRequestSubjects, loadBatchProfiles, readBatchKey, saveBatchKey, selectBatchRecords, validateBatchResult } from "../src/features/identity/permission-batch.js";

const user = { username: "manager", tenant_id: "company" };
const department = { scope_type: "department", tenant_id: "company", department_id: "sales" };
const app = { ...department, scope_type: "application", application_id: "support" };
const profile = id => ({ policy_mode: "v2", principal: { id, revision: 7, is_active: true, tenant_id: "company" }, memberships: [], role_bindings: [], resource_grants: [] });
const request = (id, subject, scope = app) => ({ id, subject_id: subject, scope, revision: 3, status: "pending", items: [{ id: "basic", kind: "resource", resource_type: "agent_installation", action: "run" }, { id: "export", kind: "resource", action: "history.export" }] });
const result = (items, key = "original-key") => ({ actor_id: user.username, actor_tenant_id: user.tenant_id, change: { kind: "authorization", idempotency_key: key }, items: items.map((status, index) => ({ index, status, subject_id: `user-${index}` })) });

test("Agent packages pin server configuration and widen the batch scope only for explicit new department admission", () => {
  const pack = { scope: { ...app, scope_type: "agent_installation", resource_id: "agent" }, agent_version_id: "published-v1", package_digest: "a".repeat(64), resources: [{ resource_type: "model", resource_id: "model", action: "model.generate" }] };
  const existing = profile("existing"), fresh = profile("new");
  existing.memberships = [{ id: "member", scope: department, status: "active", expires_at: "2030-01-01T00:00:00Z", revision: 4 }];
  existing.resource_grants = [{ id: "other-department-grant" }];
  const options = { user, profiles: { existing, new: fresh }, principals: [{ id: "existing" }, { id: "new" }], pack, joinDepartment: true, reason: "Explicit business onboarding", key: "package-key", newID: () => "new-member" };
  const command = agentUseBatchCommand(options);
  assert.deepEqual(command.scope, department);
  assert.equal(command.items[0].authorization.memberships, undefined);
  assert.equal(command.items[0].authorization.revoke_grant_ids, undefined);
  assert.equal(command.items[0].authorization.resource_grants, undefined);
  assert.equal(command.items[0].authorization.role_bindings, undefined);
  assert.equal(command.items[0].authorization.agent_use.package_digest, pack.package_digest);
  assert.equal(command.items[1].authorization.memberships[0].id, "new-member");
  const noAdmission = agentUseBatchCommand({ ...options, joinDepartment: false });
  assert.deepEqual(noAdmission.scope, app);
  assert.ok(noAdmission.items.every(item => !item.authorization.memberships));
  command.items[0].authorization.agent_use.scope.resource_id = "changed";
  assert.equal(pack.scope.resource_id, "agent");
  assert.equal(existing.resource_grants[0].id, "other-department-grant");
});

test("Agent opening never silently renews an expired, revoked or future department membership", () => {
  const pack = { scope: { ...app, scope_type: "agent_installation", resource_id: "agent" }, agent_version_id: "published-v1", package_digest: "a".repeat(64) };
  for (const member of [{ status: "active", expires_at: "2020-01-01T00:00:00Z" }, { status: "revoked" }, { status: "active", starts_at: "2030-01-01T00:00:00Z" }]) {
    const existing = profile("existing");
    existing.memberships = [{ id: "member", scope: department, revision: 4, ...member }];
    const command = agentUseBatchCommand({ user, profiles: { existing }, principals: [{ id: "existing" }], pack, joinDepartment: true, reason: "Review use", key: "package-key", newID: () => { throw new Error("unexpected renewal"); } });
    assert.equal(command.items[0].authorization.memberships, undefined);
    assert.deepEqual(existing.memberships[0], { id: "member", scope: department, revision: 4, ...member });
  }
});

test("Agent package reads keep exact scope and never trust a client-supplied actor or company", async () => {
  const calls = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 200, headers: { get: () => "application/json" }, json: async () => ({}) };
  } });
  await client.identityAgentUsePackage({ department_id: "sales", application_id: "support", installation_id: "agent/one" });
  const requestURL = new URL(calls[0].url, "http://localhost");
  assert.equal(requestURL.pathname.endsWith("/identity/agent-use-package"), true);
  assert.equal(calls[0].options.method || "GET", "GET");
  assert.equal(calls[0].options.body, undefined);
  assert.equal(requestURL.searchParams.get("installation_id"), "agent/one");
  assert.equal(requestURL.searchParams.get("tenant_id"), null);
  assert.equal(requestURL.searchParams.get("actor_id"), null);
});

test("cross-page selection preserves people outside the current page and rejects overflow atomically", () => {
  const first = [{ id: "off-page" }];
  const selected = selectBatchRecords(first, [{ id: "this-page" }], true);
  assert.deepEqual(selectBatchRecords(selected, [{ id: "this-page" }], false), first);
  const fifty = Array.from({ length: 50 }, (_, index) => ({ id: String(index) }));
  assert.throws(() => selectBatchRecords(fifty, [{ id: "51" }], true), /50/);
  assert.equal(fifty.length, 50);
});

test("batch queries are reads and explicit continuation and cancellation send only the original key", async () => {
  const calls = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    calls.push({ url, options }); return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  } });
  const command = { scope: department, kind: "authorization", idempotency_key: "original-key", items: [], reason: "reviewed" };
  await client.previewPermissionBatch(command); await client.createPermissionBatch({ ...command, plan_digest: "pinned" });
  await client.permissionBatch("original-key"); await client.continuePermissionBatch("original-key"); await client.cancelPermissionBatch("original-key");
  assert.deepEqual(calls.map(call => [call.url, call.options.method]), [
    ["/api/modules/identity/permission-batches:preview", "POST"], ["/api/modules/identity/permission-batches", "POST"],
    ["/api/modules/identity/permission-batches/original-key", "GET"], ["/api/modules/identity/permission-batches/original-key:continue", "POST"], ["/api/modules/identity/permission-batches/original-key:cancel", "POST"]
  ]);
  assert.equal(calls[2].options.body, undefined);
  assert.deepEqual(JSON.parse(calls[3].options.body), {});
  assert.deepEqual(JSON.parse(calls[4].options.body), {});
  assert.equal(JSON.parse(calls[1].options.body).plan_digest, "pinned");
});

test("an unknown write outcome stops without retrying or generating another batch", async () => {
  let calls = 0;
  const client = { continuePermissionBatch: async key => {
    assert.equal(key, "original-key"); calls++;
    if (calls === 1) return result(["succeeded", "pending"]);
    throw new Error("lost response after server commit");
  } };
  const progress = [];
  await assert.rejects(continueBatchSteps(client, { key: "original-key", batch: result(["pending", "pending"]), user, kind: "authorization", onResult: value => progress.push(value) }), /lost response/);
  assert.equal(calls, 2);
  assert.equal(progress.length, 1);
  assert.equal(batchCounts(progress[0].items).succeeded, 1);
});

test("resumption skips terminal items and leaving the page stops further writes", async () => {
  let calls = 0, active = true;
  const client = { continuePermissionBatch: async () => { calls++; return result(["succeeded", "failed", "cancelled", "blocked", "pending"]); } };
  const initial = result(["succeeded", "failed", "cancelled", "blocked", "pending"]);
  await continueBatchSteps(client, { key: "original-key", batch: initial, user, kind: "authorization", isActive: () => active, onResult: () => { active = false; } });
  assert.equal(calls, 1);
  await continueBatchSteps(client, { key: "original-key", batch: result(["succeeded", "failed"]), user, kind: "authorization" });
  assert.equal(calls, 1);
});

test("batch results from another owner, company, key or malformed status cannot be continued", async () => {
  for (const wrong of [{ ...result(["pending"]), actor_id: "another" }, { ...result(["pending"]), actor_tenant_id: "foreign" }, result(["pending"], "another-key"), result(["unknown"]), { ...result(["pending"]), items: [{ index: 5, status: "pending" }] }]) {
    assert.throws(() => validateBatchResult(wrong, "original-key", user, "authorization"));
  }
});

test("recovery storage contains only the original key and storage failures prevent submission", () => {
  const values = new Map(); const storage = { getItem: key => values.get(key), setItem: (key, value) => values.set(key, value) };
  const namespace = batchStorageKey(user, "authorization");
  saveBatchKey(storage, namespace, "original-key");
  assert.equal(readBatchKey(storage, namespace), "original-key");
  assert.equal(readBatchKey(storage, batchStorageKey({ ...user, username: "another" }, "authorization")), "");
  assert.equal(readBatchKey(storage, batchStorageKey(user, "decision")), "");
  assert.throws(() => saveBatchKey({ setItem: () => {}, getItem: () => null }, namespace, "original-key"));
  assert.throws(() => saveBatchKey(null, namespace, "original-key"));
  assert.throws(() => saveBatchKey(storage, namespace, "invalid/key"));
  assert.deepEqual([...values.values()], ["original-key"]);
});

test("request batches stay in one company and use the narrowest shared management scope", () => {
  assert.deepEqual(commonRequestScope([request("a", "a"), request("b", "b")]), app);
  assert.deepEqual(commonRequestScope([request("a", "a"), request("b", "b", { ...app, application_id: "other" })]), department);
  assert.deepEqual(commonRequestScope([request("a", "a"), request("b", "b", { ...app, department_id: "other" })]), { scope_type: "tenant", tenant_id: "company" });
  assert.equal(commonRequestScope([request("a", "a"), request("b", "b", { ...app, tenant_id: "foreign" })]), null);
  assert.equal(commonRequestScope([request("a", "a", { scope_type: "application", tenant_id: "company" })]), null);
});

test("approval requires explicit items and separates multiple requests from the same user", () => {
  const requests = [request("a", "alice"), request("b", "bob")];
  const options = { user, requests, profiles: { alice: profile("alice"), bob: profile("bob") }, approved: { a: ["basic"], b: ["basic"] }, mode: "approve", reason: " reviewed ", key: "key" };
  const command = decisionBatchCommand(options);
  assert.equal(command.items[0].decision.expected_subject_revision, 7);
  assert.deepEqual(command.items[0].decision.approved_item_ids, ["basic"]);
  assert.equal(command.reason, "reviewed");
  assert.throws(() => decisionBatchCommand({ ...options, approved: { a: ["basic"] } }));
  assert.throws(() => decisionBatchCommand({ ...options, approved: { a: ["not-requested"], b: ["basic"] } }));
  assert.deepEqual(duplicateRequestSubjects([requests[0], request("other", "alice")]), ["alice"]);
  assert.throws(() => decisionBatchCommand({ ...options, requests: [requests[0], request("other", "alice")] }));
  assert.deepEqual(decisionBatchCommand({ ...options, mode: "reject" }).items.map(item => item.decision.decision), ["rejected", "rejected"]);
  assert.deepEqual(basicRequestedItems({ items: [...requests[0].items, { id: "admin", kind: "role", role_code: "super_admin" }, { id: "fake", kind: "resource", resource_type: "model", action: "run" }] }), ["basic"]);
});

test("department batches preserve existing validity and other departments unless an explicit role change is selected", () => {
  const alice = profile("alice");
  alice.memberships = [{ id: "member-old", revision: 4, scope: department, status: "active", starts_at: "2026-10-12T00:00:00Z", expires_at: "2026-11-01T00:00:00Z" }];
  alice.role_bindings = [{ id: "admin-future", role_code: "department_admin", status: "active", scope: department, starts_at: "2026-10-12T00:00:00Z" }, { id: "other-admin", role_code: "department_admin", status: "active", scope: { ...department, department_id: "other" } }];
  alice.resource_grants = [{ id: "explicit-deny", effect: "deny", status: "active" }];
  const options = { user, principals: [{ id: "alice" }], profiles: { alice }, department, role: "keep", reason: "admit", key: "key", newID: () => "new-member" };
  const keep = departmentBatchCommand(options).items[0].authorization;
  assert.equal(keep.memberships[0].expires_at, alice.memberships[0].expires_at);
  assert.equal(keep.memberships[0].starts_at, alice.memberships[0].starts_at);
  assert.equal(keep.revoke_binding_ids, undefined);
  assert.equal(keep.revoke_grant_ids, undefined);
  const demote = departmentBatchCommand({ ...options, role: "member" }).items[0].authorization;
  assert.deepEqual(demote.revoke_binding_ids, ["admin-future"]);
  const appoint = departmentBatchCommand({ ...options, role: "administrator", expiresAt: "2026-10-20T00:00:00Z" }).items[0].authorization;
  assert.equal(appoint.preset.preset_version, 2);
  assert.equal(appoint.preset.expires_at, appoint.memberships[0].expires_at);
  assert.throws(() => departmentBatchCommand({ ...options, principals: [{ id: user.username }], profiles: { [user.username]: profile(user.username) } }));
  assert.throws(() => departmentBatchCommand({ ...options, department: { ...department, tenant_id: "foreign" } }));
  assert.equal(alice.role_bindings.length, 2);
  assert.equal(alice.resource_grants[0].effect, "deny");
});

test("profile refresh bounds concurrency and deduplicates people before preview", async () => {
  let active = 0, maximum = 0, calls = 0;
  const values = await loadBatchProfiles({ identityAccessProfile: async id => {
    active++; calls++; maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 1)); active--; return profile(id);
  } }, [...Array.from({ length: 13 }, (_, index) => `user-${index}`), "user-0"]);
  assert.equal(calls, 13);
  assert.equal(Object.keys(values).length, 13);
  assert.equal(maximum, 5);
});
