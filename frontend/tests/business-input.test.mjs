import test from "node:test";
import assert from "node:assert/strict";
import { parseBusinessInput } from "../src/features/agent-workspace/business-input.js";

test("preserves each Agent's business fields and typed values", () => {
  for (const input of [
    { service: "orders", symptom: "slow", observations: "deployment" },
    { question: "index sync", top_k: 3, cache_mode: "use" },
    { ticket_id: "DEMO-001", summary: "timeout", details: "request" },
  ]) assert.deepEqual(parseBusinessInput(JSON.stringify(input)), input);
});

test("rejects malformed and non-object business input before submission", () => {
  for (const input of ["plain text", "{", "null", "[]", "3", '"text"', "true"]) {
    assert.throws(() => parseBusinessInput(input));
  }
});
