import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient } from "../src/api.js";

const json = (status, headers = {}) => new Response(JSON.stringify({ message: "response" }), {
  status, headers: { "content-type": "application/json", ...headers }
});

test("concurrent gateway authentication failures share one refresh and preserve request identity", async () => {
  let refreshed = false, refreshCalls = 0;
  let finishRefresh;
  const delayed = new Promise(resolve => { finishRefresh = resolve; });
  const requests = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    if (url === "/auth/refresh") { refreshCalls++; await delayed; refreshed = true; return json(200); }
    requests.push({ url, options });
    return refreshed ? json(200) : json(401, { "X-Authentication-Error": "access_token_invalid" });
  } });
  const command = { idempotency_key: "stable-key", plan_digest: "approved-digest" };
  const first = client.commitIdentityAuthorization(command);
  const second = client.identityWorkspaces();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(refreshCalls, 1);
  finishRefresh();
  await Promise.all([first, second]);
  assert.equal(refreshCalls, 1);
  assert.equal(requests.length, 4);
  const writes = requests.filter(item => item.url.endsWith("/authorization-changes"));
  assert.equal(writes.length, 2);
  assert.equal(writes[0].options, writes[1].options);
  assert.deepEqual(JSON.parse(writes[1].options.body), command);
});

test("business unauthorized and failed renewal do not resubmit a mutation", async () => {
  for (const gatewayFailure of [false, true]) {
    let requests = 0, refreshCalls = 0;
    const client = createApiClient({ fetchImpl: async (url) => {
      if (url === "/auth/refresh") { refreshCalls++; return json(503); }
      requests++;
      return json(401, gatewayFailure ? { "X-Authentication-Error": "access_token_invalid" } : {});
    } });
    await assert.rejects(client.commitIdentityAuthorization({}), error => error.status === 401);
    assert.equal(requests, 1);
    assert.equal(refreshCalls, gatewayFailure ? 1 : 0);
  }
});

test("two tabs rotate the shared cookie once and never store bearer credentials", async () => {
  let queue = Promise.resolve();
  const locks = { request(name, callback) {
    assert.equal(name, "agentplug-auth-refresh");
    const result = queue.then(callback);
    queue = result.catch(() => {});
    return result;
  } };
  let accessValid = false, rotations = 0, probes = 0, writes = 0;
  let releaseRotation;
  const delayed = new Promise(resolve => { releaseRotation = resolve; });
  const fetchImpl = async (url) => {
    if (url === "/auth/refresh") {
      rotations++;
      await delayed;
      accessValid = true;
      return json(200);
    }
    if (url === "/auth/me") probes++;
    if (!accessValid) return json(401, { "X-Authentication-Error": "access_token_invalid" });
    if (url.endsWith("/authorization-changes")) writes++;
    return json(200);
  };
  const tabs = [createApiClient({ fetchImpl, refreshLocks: locks }), createApiClient({ fetchImpl, refreshLocks: locks })];
  const requests = tabs.map(client => client.commitIdentityAuthorization({ idempotency_key: "stable" }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(rotations, 1);
  releaseRotation();
  await Promise.all(requests);
  assert.equal(rotations, 1);
  assert.equal(probes, 2);
  assert.equal(writes, 2);
});

test("cross-tab recheck outage leaves the refresh credential untouched", async () => {
  let rotations = 0;
  const client = createApiClient({ refreshLocks: { request: (_, callback) => callback() }, fetchImpl: async url => {
    if (url === "/auth/refresh") rotations++;
    if (url === "/auth/me") return json(503);
    return json(401, { "X-Authentication-Error": "access_token_invalid" });
  } });
  await assert.rejects(client.identityWorkspaces(), error => error.status === 401);
  assert.equal(rotations, 0);
});
