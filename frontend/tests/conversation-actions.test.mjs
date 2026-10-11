import test from "node:test";
import assert from "node:assert/strict";
import { conversationActions, applyConversationBatch, canStartAgentRun } from "../src/features/agent-workspace/conversation-actions.js";

test("Agent discovery does not grant execution and v2 cannot use missing/global run hints", () => {
  const user = { policy_mode: "v2", roles: ["admin"], capabilities: ["run"] };
  const agent = { access_status: "granted", permissions: { discover: true } };
  assert.equal(canStartAgentRun(user, agent), false);
  assert.equal(canStartAgentRun(user, { ...agent, permissions: { discover: true, run: true } }), true);
  assert.equal(canStartAgentRun(user, { ...agent, permissions: { discover: false, run: true } }), false);
  assert.equal(canStartAgentRun(user, { ...agent, permissions: { discover: true, run: "true" } }), false);
  assert.equal(canStartAgentRun(user, { access_status: "granted" }), false);
  assert.equal(canStartAgentRun({ policy_mode: "legacy" }, agent), true);
  assert.equal(canStartAgentRun({ policy_mode: "unknown" }, agent), false);
});

test("v2 history controls use exact current object permissions, never global roles", () => {
  const user = { username: "reader", policy_mode: "v2", roles: ["admin", "operator"], capabilities: ["run", "history.share"] };
  const session = { id: "history", owner_id: "other", can_continue: true, permissions: { "history.read": true } };
  assert.deepEqual(conversationActions(user, session), { read: true, continue: false, revise: false, regenerate: false, share: false, export: false, delete: false });
  assert.equal(conversationActions(user, { ...session, permissions: {} }).read, false);
  assert.equal(conversationActions(user, { ...session, permissions: { "history.share": "true", "history.export": 1 } }).share, false);
  for (const action of ["history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request"]) {
    const result = conversationActions(user, { ...session, permissions: { [action]: true } });
    assert.equal(Object.values(result).filter(Boolean).length, 1);
    assert.equal(result.continue, false);
  }
});

test("continue requires live run and continue grants plus resumable history", () => {
  const user = { policy_mode: "v2" };
  const session = { id: "history", can_continue: true, permissions: { run: true, "history.continue": true } };
  assert.equal(conversationActions(user, session).continue, true);
  assert.equal(conversationActions(user, { ...session, can_continue: false }).continue, false);
  assert.equal(conversationActions(user, { ...session, permissions: { run: true } }).continue, false);
  assert.equal(conversationActions(user, { ...session, permissions: { "history.continue": true } }).continue, false);
  assert.equal(conversationActions(user, null).continue, false);
});

test("legacy ownership remains compatible, unknown modes and missing sessions fail closed", () => {
  const session = { id: "history", owner_id: "alice" };
  for (const policy_mode of [undefined, "legacy", "shadow"]) assert.equal(conversationActions({ username: "alice", policy_mode }, session).share, true);
  assert.equal(conversationActions({ username: "bob", policy_mode: "legacy" }, session).share, false);
  assert.equal(conversationActions({ username: "alice", policy_mode: "invalid" }, session).read, false);
  assert.equal(conversationActions({ username: "alice" }, {}).read, false);
});

test("batch calls each source once and preserves individual revoked failures", async () => {
  const calls = [];
  const result = await applyConversationBatch(["allowed", "revoked", "allowed-next"], async id => {
    calls.push(id);
    if (id === "revoked") throw new Error("权限已撤销");
    return { id: `export-${id}` };
  });
  assert.deepEqual(calls, ["allowed", "revoked", "allowed-next"]);
  assert.deepEqual(result.succeeded, ["allowed", "allowed-next"]);
  assert.deepEqual(result.failed, [{ id: "revoked", message: "权限已撤销" }]);
  assert.deepEqual(result.values, [{ id: "export-allowed" }, { id: "export-allowed-next" }]);
});
