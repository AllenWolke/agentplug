import test from "node:test";
import assert from "node:assert/strict";
import { auditMetadataQuery } from "../src/features/identity/audit-query.js";

test("audit scope changes remove stale lower organization axes", () => {
  const form = { tenant_id: " tenant ", department_id: "dept", application_id: "app", task_id: " task ", trace_id: "" };
  assert.deepEqual(auditMetadataQuery({ ...form, scope_type: "global" }), { scope_type: "global", task_id: "task", page: 1, page_size: 20 });
  assert.deepEqual(auditMetadataQuery({ ...form, scope_type: "department" }, 2), { scope_type: "department", tenant_id: "tenant", department_id: "dept", task_id: "task", page: 2, page_size: 20 });
  assert.equal(auditMetadataQuery({ ...form, scope_type: "tenant" }).application_id, undefined);
});

test("audit queries require concrete organization coordinates", () => {
  assert.throws(() => auditMetadataQuery({ scope_type: "application", tenant_id: "t", department_id: "d" }));
  assert.throws(() => auditMetadataQuery({ scope_type: "unknown" }));
  assert.deepEqual(auditMetadataQuery({ scope_type: "global" }), { scope_type: "global", page: 1, page_size: 20 });
});
