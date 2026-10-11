import test from "node:test";
import assert from "node:assert/strict";
import { policyAssetActions } from "../src/features/policy-asset/policy-asset-access.js";
import { canManagePolicyAssets } from "../src/config.js";

test("Prompt and Tool actions do not confer snapshot publication or other asset writes", () => {
  for (const [action, type] of [["prompt.manage", "prompt"], ["tool.manage", "tool"]]) {
    const user = { policy_mode: "v2", roles: ["admin"], capabilities: [action] };
    assert.equal(canManagePolicyAssets(user), true);
    assert.deepEqual(policyAssetActions(user), { types: [type], snapshot: false });
  }
  const publisher = { policy_mode: "v2", capabilities: ["policy.manage"] };
  assert.deepEqual(policyAssetActions(publisher), { types: ["model", "memory", "knowledge", "runtime"], snapshot: true });
  assert.deepEqual(policyAssetActions({ policy_mode: "v2", capabilities: [], roles: ["admin"] }), { types: [], snapshot: false });
  assert.equal(canManagePolicyAssets({ policy_mode: "v2", capabilities: [], roles: ["admin"] }), false);
});
