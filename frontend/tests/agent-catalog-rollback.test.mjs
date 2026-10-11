import test from "node:test";
import assert from "node:assert/strict";
import { publishedRollbackOptions } from "../src/features/agent-catalog/rollback-options.js";

test("rollback options include only a different immutable published version", () => {
  const versions = [
    { id: "v3", semantic_version: "3.0.0", status: "published" },
    { id: "v2", semantic_version: "2.0.0", status: "published" },
    { id: "v1", semantic_version: "1.0.0", status: "draft" },
    { id: "v0", semantic_version: "0.9.0", status: "published" },
    { id: "", semantic_version: "0.8.0", status: "published" },
  ];
  assert.deepEqual(publishedRollbackOptions(versions, "v3").map((version) => version.id), ["v2", "v0"]);
});

test("rollback options fail closed for invalid or missing version lists", () => {
  assert.deepEqual(publishedRollbackOptions(null, "v3"), []);
  assert.deepEqual(publishedRollbackOptions([{ semantic_version: "1.0.0", status: "published" }], "v3"), []);
});
