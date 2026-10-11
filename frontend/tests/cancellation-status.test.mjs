import test from "node:test";
import assert from "node:assert/strict";
import { formatStatus, statusTone } from "../src/format.js";

test("pending cancellation is not displayed as completed cancellation", () => {
  assert.equal(formatStatus("cancelling"), "取消确认中");
  assert.equal(statusTone("cancelling"), "warning");
  assert.equal(formatStatus("cancelled"), "已取消");
  assert.equal(formatStatus("recovering"), "恢复前停止确认中");
  assert.equal(statusTone("recovering"), "warning");
});
