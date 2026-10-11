import test from "node:test";
import assert from "node:assert/strict";
import { groupResourceGrants, toggleGroupAllows } from "../src/features/identity/grant-groups.js";

test("compact grouping preserves each independent source and explicit deny", () => {
  const grants = [{ id: "source-a", resource_type: "agent_installation", resource_id: "agent-a", agent_instance_id: "agent-a", action: "run", effect: "allow" }, { id: "source-b", resource_type: "agent_installation", resource_id: "agent-a", agent_instance_id: "agent-a", action: "run", effect: "allow" }, { id: "deny", resource_type: "agent_installation", resource_id: "agent-a", agent_instance_id: "agent-a", action: "run", effect: "deny" }];
  const groups = groupResourceGrants(grants);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].grants.map(item => item.id), ["source-a", "source-b", "deny"]);
  assert.deepEqual(toggleGroupAllows(["unrelated"], groups[0].grants), ["unrelated", "source-a", "source-b"]);
  assert.deepEqual(toggleGroupAllows(["unrelated", "source-a", "source-b", "deny"], groups[0].grants), ["unrelated", "deny"]);
});

test("the same dependency in two Agent installations remains two distinct groups", () => {
  const grants = ["agent-a", "agent-b"].map((installation, index) => ({ id: String(index), resource_type: "model", resource_id: "shared-model", agent_instance_id: installation, effect: "allow" }));
  assert.equal(groupResourceGrants(grants).length, 2);
});
