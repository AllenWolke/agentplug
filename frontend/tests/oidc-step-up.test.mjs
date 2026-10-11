import test from "node:test";
import assert from "node:assert/strict";
import { authenticateOIDC } from "../src/features/identity/oidc-step-up.js";
import { createApiClient } from "../src/api.js";

function fixture() {
  const listeners = new Map();
  const popup = { closed: false, location: { href: "about:blank" }, close() { this.closed = true; } };
  const browser = { location: { origin: "https://console.example" }, open: () => popup,
    addEventListener: (name, callback) => listeners.set(name, callback),
    removeEventListener: (name, callback) => { if (listeners.get(name) === callback) listeners.delete(name); } };
  const state = "s".repeat(43), token = "p".repeat(43);
  const begin = async () => ({ state, authorization_url: "https://issuer.example/authorize" });
  const send = patch => listeners.get("message")?.({ origin: browser.location.origin, source: popup,
    data: { type: "agentplug.oidc.step-up", state, step_up_token: token, expires_at: new Date(Date.now() + 60000).toISOString() }, ...patch });
  return { browser, popup, listeners, state, token, begin, send };
}

test("OIDC proof requires the exact popup, origin and flow; listeners are removed after one result", async () => {
  const f = fixture();
  const promise = authenticateOIDC({ browser: f.browser, begin: f.begin, input: { action: "delegation.manage" } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.popup.location.href, "https://issuer.example/authorize");
  f.send({ origin: "https://attacker.example" });
  f.send({ source: {} });
  f.send({ data: { type: "agentplug.oidc.step-up", state: "another-flow", step_up_token: f.token } });
  assert.equal(f.popup.closed, false);
  f.send();
  assert.equal((await promise).step_up_token, f.token);
  assert.equal(f.popup.closed, true);
  assert.equal(f.listeners.size, 0);
});

test("cancellation while starting closes the popup and prevents late navigation", async () => {
  const f = fixture(), controller = new AbortController();
  let release;
  const promise = authenticateOIDC({ browser: f.browser, begin: () => new Promise(resolve => { release = resolve; }), signal: controller.signal });
  await Promise.resolve();
  controller.abort();
  await assert.rejects(promise, /取消/);
  release({ state: f.state, authorization_url: "https://issuer.example/authorize" });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.popup.location.href, "about:blank");
  assert.equal(f.listeners.size, 0);
});

test("invalid provider URL, popup blocking, provider failure and expiration never return a proof", async () => {
  const blocked = fixture(); blocked.browser.open = () => null;
  await assert.rejects(authenticateOIDC({ browser: blocked.browser, begin: blocked.begin }), /弹出/);
  const insecure = fixture();
  await assert.rejects(authenticateOIDC({ browser: insecure.browser, begin: async () => ({ state: insecure.state, authorization_url: "http://issuer.example" }) }), /地址/);
  for (const data of [{ error: "OIDC_STEP_UP_FAILED" }, { step_up_token: "invalid" }, { step_up_token: "p".repeat(43), expires_at: new Date(Date.now() - 1000).toISOString() }]) {
    const f = fixture();
    const promise = authenticateOIDC({ browser: f.browser, begin: f.begin });
    await new Promise(resolve => setImmediate(resolve));
    f.send({ data: { type: "agentplug.oidc.step-up", state: f.state, ...data } });
    await assert.rejects(promise);
    assert.equal(f.listeners.size, 0);
  }
});

test("step-up APIs use the same-origin gateway and preserve the preview digest", async () => {
  const calls = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return Response.json({ method: "oidc", available: true });
  } });
  assert.equal((await client.identityStepUpMethod()).method, "oidc");
  const input = { action: "administrator.appoint", request_digest: "a".repeat(64) };
  await client.beginOIDCStepUp(input);
  assert.equal(calls[0].url, "/auth/step-up/method");
  assert.equal(calls[1].url, "/auth/step-up/oidc/start");
  assert.deepEqual(JSON.parse(calls[1].options.body), input);
  assert.equal(calls[1].options.credentials, "same-origin");
});
