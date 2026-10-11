import test from "node:test";
import assert from "node:assert/strict";
import { publishedAgentVersion } from "../src/features/agent-workspace/published-agent-version.js";

test("uses the current immutable version from the scoped catalog", () => {
  const versionID = publishedAgentVersion([
    { agent_id: "ops-assistant", access_status: "granted", version_id: "published-check-v3" },
  ], "ops-assistant");
  assert.equal(versionID, "published-check-v3");
});

test("does not resolve an Agent outside the caller grant", () => {
  assert.throws(
    () => publishedAgentVersion([{ agent_id: "ops-assistant", access_status: "restricted", version_id: "v1" }], "ops-assistant"),
    /没有该 Agent 的运行授权/,
  );
});

test("fails closed when the published version is missing instead of using a hard-coded legacy ID", () => {
  assert.throws(
    () => publishedAgentVersion([{ agent_id: "document-assistant", access_status: "granted" }], "document-assistant"),
    /未返回当前发布版本/,
  );
});
