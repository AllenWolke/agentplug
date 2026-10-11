import test from "node:test";
import assert from "node:assert/strict";
import { loadAgentAccessReview, loadEnrollmentReview } from "../src/features/identity/access-admin-loader.js";

test("legacy enrollment failure is isolated from modular Identity access requests", async () => {
  const api = {
    userEnrollments: async () => { throw new Error("legacy enrollment route is unavailable"); },
    myAgentCatalog: async () => ({ items: [{ agent_id: "qa-install" }] }),
    identityAgentAccessRequests: async () => ({ items: [{ id: "request-1", status: "pending" }] })
  };

  await assert.rejects(loadEnrollmentReview(api, "pending_review"), /legacy enrollment route is unavailable/);
  assert.deepEqual(await loadAgentAccessReview(api), {
    catalog: [{ agent_id: "qa-install" }],
    accessRequests: [{ id: "request-1", status: "pending" }]
  });
});

test("agent access panel depends only on Identity and Catalog module contracts", async () => {
  const calls = [];
  const api = {
    userEnrollments: async () => { throw new Error("must not be called by Identity loader"); },
    myAgentCatalog: async () => { calls.push("catalog"); return []; },
    identityAgentAccessRequests: async (query) => { calls.push(query); return [] }
  };

  const result = await loadAgentAccessReview(api);
  assert.deepEqual(result, { catalog: [], accessRequests: [] });
  assert.deepEqual(calls, ["catalog", { status: "pending" }]);
});
