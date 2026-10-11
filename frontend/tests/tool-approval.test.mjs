import test from "node:test";
import assert from "node:assert/strict";
import { createApiClient } from "../src/api.js";
import { createToolApprovalFlow } from "../src/features/agent-workspace/tool-approval.js";

const operation = () => ({ run_id: "run-a", name: "ticket.update", call_id: "call-a", payload: { status: "resolved" } });
const preview = () => ({ claims: { version: "tool-confirmation/v1", tool_name: "ticket.update", call_id: "call-a", expires_at: 120 }, request_digest: "bound" });

test("approval APIs use only the cookie module control plane", async () => {
  const requests = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    requests.push({ url, options }); return new Response(JSON.stringify({ data: {} }), { headers: { "content-type": "application/json" } });
  } });
  await client.previewToolApproval(operation());
  await client.toolApprovalStepUp({ current_password: "fixture" });
  await client.approveToolOperation({ step_up_token: "proof" });
  await client.revokeToolOperation({ step_up_token: "proof" });
  assert.deepEqual(requests.map(item => item.url), ["preview", "step-up", "approve", "revoke"].map(action => `/api/modules/tool-approvals/${action}`));
  assert.ok(requests.every(item => item.options.method === "POST" && item.options.credentials === "same-origin"));
});

test("fresh authentication binds frozen parameters and keeps password out of commit", async () => {
  const calls = [];
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => preview(),
    toolApprovalStepUp: async command => { calls.push(command); return { step_up_token: "proof" }; },
    approveToolOperation: async command => { calls.push(command); return { confirmation_token: "opaque" }; },
  }, () => 1000);
  const input = operation(); await flow.preview(input); input.payload.status = "deleted";
  assert.equal((await flow.commit("approve", "fixture")).confirmation_token, "opaque");
  assert.equal(calls[0].operation.payload.status, "resolved");
  assert.equal(calls[0].action, "tool.approval.approve");
  assert.equal(calls[0].current_password, "fixture");
  assert.equal(calls[1].current_password, undefined);
  assert.equal(calls[1].operation.call_id, "call-a");
});

test("operation invalidation during authentication prevents issuing approval", async () => {
  let issue = 0;
  let authenticate;
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => preview(),
    toolApprovalStepUp: async () => new Promise(resolve => { authenticate = resolve; }),
    approveToolOperation: async () => { issue++; },
  }, () => 1000);
  await flow.preview(operation());
  const pending = flow.commit("approve", "fixture"); flow.invalidate();
  authenticate({ step_up_token: "proof" });
  await assert.rejects(pending, /变更/); assert.equal(issue, 0);
});

test("expired preview and lost submission are never automatically resubmitted", async () => {
  let now = 1000, calls = 0;
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => preview(),
    toolApprovalStepUp: async () => ({ step_up_token: "proof" }),
    approveToolOperation: async () => { calls++; throw new Error("unknown response"); },
  }, () => now);
  await flow.preview(operation()); await assert.rejects(flow.commit("approve", "fixture"), /unknown/);
  assert.equal(calls, 1);
  now = 120000; await assert.rejects(flow.commit("approve", "fixture"), /到期/);
  assert.equal(calls, 1);
});

test("OIDC-only approval and revocation use the immutable digest without a password fallback", async () => {
  const calls = [], value = preview();
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => value,
    toolApprovalStepUp: async () => { throw new Error("password endpoint must not be used"); },
    approveToolOperation: async command => { calls.push(command); return { confirmation_token: "opaque" }; },
    revokeToolOperation: async command => { calls.push(command); return { revoked: true }; },
  }, () => 1000);
  await flow.preview(operation());
  value.request_digest = "substituted";
  const authenticate = async input => {
    assert.ok(Object.isFrozen(input));
    assert.equal(input.request_digest, "bound");
    calls.push(input);
    return { step_up_token: "oidc-proof" };
  };
  await flow.commit("approve", "", authenticate);
  await flow.commit("revoke", "", authenticate);
  assert.equal(calls[0].action, "tool.approval.approve");
  assert.equal(calls[2].action, "tool.approval.revoke");
  assert.equal(calls[1].step_up_token, "oidc-proof");
  assert.equal(calls[3].step_up_token, "oidc-proof");
  assert.ok(calls.every(value => !("current_password" in value)));
});

test("expired preview after provider authentication and denied authentication never issue approval", async () => {
  let now = 1000, issued = 0, passwordCalls = 0;
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => preview(),
    toolApprovalStepUp: async () => { passwordCalls++; },
    approveToolOperation: async () => { issued++; },
  }, () => now);
  await flow.preview(operation());
  await assert.rejects(flow.commit("approve", "", async () => { throw new Error("provider rejected identity"); }), /provider/);
  await assert.rejects(flow.commit("approve", "", async () => { now = 120000; return { step_up_token: "proof" }; }), /到期/);
  assert.equal(issued, 0);
  assert.equal(passwordCalls, 0);
});

test("operation change during OIDC verification prevents late approval", async () => {
  let release, issued = 0;
  const flow = createToolApprovalFlow({
    previewToolApproval: async () => preview(),
    approveToolOperation: async () => { issued++; },
  }, () => 1000);
  await flow.preview(operation());
  const request = flow.commit("approve", "", () => new Promise(resolve => { release = resolve; }));
  flow.invalidate();
  release({ step_up_token: "oidc-proof" });
  await assert.rejects(request, /变更/);
  assert.equal(issued, 0);
});
