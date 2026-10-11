import test from "node:test";
import assert from "node:assert/strict";
import { canSubmitCatalogRelease, canApproveCatalogRelease } from "../src/features/agent-catalog/release-actions.js";

test("release approval requires its own action and a different known submitter", () => {
  const item = { status: "evaluated", submitted_by: "alice" };
  const bob = { username: "bob", policy_mode: "v2", capabilities: ["release.approve"] };
  assert.equal(canApproveCatalogRelease(bob, item), true);
  assert.equal(canSubmitCatalogRelease(bob), false);
  assert.equal(canApproveCatalogRelease({ ...bob, username: "alice" }, item), false);
  assert.equal(canApproveCatalogRelease(bob, { status: "evaluated" }), false);
  assert.equal(canApproveCatalogRelease(bob, { ...item, status: "published" }), false);
  const submitter = { username: "bob", policy_mode: "v2", capabilities: ["release.submit"] };
  assert.equal(canSubmitCatalogRelease(submitter), true);
  assert.equal(canApproveCatalogRelease(submitter, item), false);
  const manager = { username: "bob", policy_mode: "v2", capabilities: ["catalog.manage"], roles: ["admin", "platform_admin"] };
  assert.equal(canSubmitCatalogRelease(manager), false);
  assert.equal(canApproveCatalogRelease(manager, item), false);
});
