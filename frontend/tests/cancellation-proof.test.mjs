import test from "node:test";
import assert from "node:assert/strict";
import { checkedCancellation, formatCancellationStatus } from "../src/features/agent-workspace/cancellation-state.js";

const progress = (patch = {}) => ({
  version: "cancellation-compensation/v1", cancellation_id: "a".repeat(64), phase: "compensating",
  stop_confirmed: true, total: 2, compensated: 1, no_effect: 0, unresolved: 1, needs_attention: 0, ...patch
});
const view = (p, disposition = "in_progress") => ({ version: "cancellation-state/v1", disposition, progress: p });

test("Agent stop and accepted cancellation still display unfinished rollback", () => {
  assert.match(formatCancellationStatus("cancelling", view(progress())), /正在撤销变更.*1\/2/);
  assert.notEqual(formatCancellationStatus("cancellation_requested"), "已取消");
  assert.notEqual(formatCancellationStatus("cancelling"), "已取消");
});

test("historical cancelled status cannot invent a compensation proof", () => {
  assert.equal(formatCancellationStatus("cancelled"), "历史执行已终止，撤销未验证");
  assert.equal(checkedCancellation("cancelled").disposition, "historical_unverified");
});

test("only confirmed stop with every disposition resolved displays cancelled", () => {
  const complete = view(progress({ phase: "complete", compensated: 1, no_effect: 1, unresolved: 0 }), "verified");
  assert.equal(formatCancellationStatus("cancelled", complete), "已取消");
  assert.throws(() => checkedCancellation("cancelling", complete));
  assert.throws(() => checkedCancellation("cancelled", view(progress(), "verified")));
  assert.throws(() => checkedCancellation("cancelled", view(progress({ phase: "complete", unresolved: 0, no_effect: 1, stop_confirmed: false }), "verified")));
});

test("unknown effects and compensation conflicts cannot pass the completion gate", () => {
  const blocked = view(progress({ phase: "needs_attention", needs_attention: 1 }));
  assert.equal(formatCancellationStatus("cancelling", blocked), "取消未完成：需要核对或补偿");
  assert.throws(() => checkedCancellation("cancelled", { ...blocked, disposition: "verified" }));
});

test("missing versions, impossible counts and inconsistent stop facts fail closed", () => {
  for (const p of [progress({ version: "future" }), progress({ unresolved: -1 }), progress({ total: 0 }),
    progress({ unresolved: 0.5 }), progress({ total: 16385 }), progress({ phase: "stopping", stop_confirmed: true }),
    progress({ phase: "needs_attention", needs_attention: 0 }), progress({ needs_attention: 1 })]) {
    assert.throws(() => checkedCancellation("cancelling", view(p)));
    assert.equal(formatCancellationStatus("cancelling", view(p)), "取消状态待核对");
  }
});

test("public cancellation projection drops unrequested sensitive fields", () => {
  const input = { ...view({ ...progress(), lease_token: "fixture-control-token" }), before_image: "fixture-private-value" };
  const checked = checkedCancellation("cancelling", input);
  assert.equal("before_image" in checked, false);
  assert.equal("lease_token" in checked.progress, false);
});
