import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createApiClient } from "../src/api.js";

test("billing requests use a narrow same-origin authenticated BFF route", async () => {
  const requests = [];
  const client = createApiClient({ fetchImpl: async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ code: 0, data: { items: [] } }), { status: 200 });
  } });
  await client.modelBillingReconciliations();
  const command = { scope_hash: "a".repeat(64), idempotency_key: "model-call", fingerprint: "b".repeat(64), decision: { id: "decision-1", outcome: "no_charge", reservation_id: "budget-1", provider_ref: "receipt-1", reason: "Vendor confirmed no charge" } };
  await client.decideModelBillingReconciliation(command);
  assert.equal(requests.length, 2);
  for (const { url, options } of requests) {
    assert.equal(url, "/api/modules/model-billing/reconciliations");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.headers["X-Internal-Token"], undefined);
  }
  assert.equal(requests[1].options.method, "POST");
  assert.deepEqual(JSON.parse(requests[1].options.body), command);
});

test("billing view matches server ID fields and never supplies approver identity", async () => {
  const source = await readFile(new URL("../src/features/model-governance/BillingReconciliation.jsx", import.meta.url), "utf8");
  assert.match(source, /idempotency_key: selected\.idempotency_key/);
  assert.doesNotMatch(source, /actor_id:|actor_tenant:|selected\.key\b/);
  assert.match(source, /Number\.isSafeInteger/);
  assert.match(source, /record\.state === "manual"/);
  assert.match(source, /受理不等于结算完成/);
});
