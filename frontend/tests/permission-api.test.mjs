import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient } from "../src/api.js";

test("human and machine access profiles preserve distinct subject types", async () => {
  const urls = [];
  const client = createApiClient({ fetchImpl: async (url) => {
    urls.push(url);
    return new Response("{}", { status: 200 });
  } });
  await client.identityAccessProfile("same.id");
  await client.identityAccessProfile("same.id", "service_principal");
  assert.equal(urls[0], "/api/modules/identity/principals/same.id/access-profile");
  assert.equal(urls[1], "/api/modules/identity/principals/same.id/access-profile?principal_type=service_principal");
});

test("permission preview and commit preserve the fixed plan and use the identity boundary", async () => {
  const requests = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  } });
  const command = { subject_id: "user-a", subject_type: "user", expected_revision: 4, idempotency_key: "request-a", reason: "岗位调整",
    preset: { preset_code: "operator", preset_version: 1, scope: { scope_type: "application", tenant_id: "t", department_id: "d", application_id: "a" }, resource_ids: ["installation-a"] } };
  await client.previewIdentityAuthorization(command);
  const commit = { ...command, plan_digest: "fixed-digest", plan_expires_at: "2026-09-30T12:00:00Z" };
  await client.commitIdentityAuthorization(commit);
  assert.equal(requests[0].url, "/api/modules/identity/authorization-changes:preview");
  assert.equal(requests[1].url, "/api/modules/identity/authorization-changes");
  assert.deepEqual(JSON.parse(requests[1].options.body), commit);
  assert.equal(requests[1].options.credentials, "same-origin");
});

test("stale authorization plans surface as conflicts without automatic resubmission", async () => {
  let calls = 0;
  const client = createApiClient({ fetchImpl: async () => {
    calls++;
    return new Response(JSON.stringify({ error: { code: "PLAN_STALE" } }), { status: 409, headers: { "content-type": "application/json" } });
  } });
  await assert.rejects(client.commitIdentityAuthorization({ plan_digest: "old" }), error => error.status === 409 && error.code === "PLAN_STALE");
  assert.equal(calls, 1);
});
