import test from "node:test";
import assert from "node:assert/strict";
import {
  canManageUsers, canAudit, defaultLanding, isAppAdmin, isIntegrationAdmin, isPlatformAdmin, isSystemAdmin, rolesOf, visibleApplications
} from "../src/config.js";
import { asItems, createRecentStore, lastDaysRange, summarizeUsage } from "../src/state.js";

class MemoryStorage {
  values = new Map();
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, String(value)); }
  removeItem(key) { this.values.delete(key); }
}

test("versioned permission administrator sees user management without inheriting cached administrator authority", () => {
  const actor = { policy_mode: "v2", roles: ["admin", "auditor"], capabilities: ["principal.read", "authorization.change"] };
  assert.equal(canManageUsers(actor), true);
  assert.equal(isSystemAdmin(actor), false);
  assert.equal(isPlatformAdmin(actor), false);
  assert.equal(canAudit(actor), false);
  assert.deepEqual(rolesOf(actor), []);
  actor.capabilities = [];
  assert.equal(canManageUsers(actor), false);
  actor.policy_mode = "unknown";
  actor.capabilities = ["principal.read", "platform.monitor"];
  assert.equal(canManageUsers(actor), false);
  assert.equal(isSystemAdmin(actor), false);
});

const user = (roles, department_id = "dept-demo", application_id = "app-demo") => ({ roles, department_id, application_id });

test("roles map to distinct management spaces", () => {
  assert.equal(isSystemAdmin(user(["admin"])), true);
  assert.equal(isSystemAdmin(user(["system_admin"])), true);
  assert.equal(isPlatformAdmin(user(["platform_admin"])), true);
  assert.equal(isAppAdmin(user(["application_admin"])), true);
  assert.equal(isAppAdmin(user(["admin"])), false);
  assert.equal(isIntegrationAdmin(user(["application_admin"])), true);
  assert.equal(isIntegrationAdmin(user(["department_admin"])), true);
  assert.equal(isIntegrationAdmin(user(["platform_admin"])), true);
  assert.equal(isIntegrationAdmin(user(["admin"])), true);
  assert.equal(isIntegrationAdmin(user(["operator"])), false);
});

test("department account only sees its authorized application", () => {
  assert.deepEqual(visibleApplications(user(["operator"])).map((item) => item.code), ["app-demo"]);
  assert.deepEqual(visibleApplications(user(["platform_admin"], "dept-platform", "app-platform-admin")), []);
  assert.equal(defaultLanding(user(["platform_admin"])), "/platform/overview");
  assert.equal(defaultLanding(user(["admin"])), "/system/operations");
});

test("recent task index deduplicates and remains bounded", () => {
  const store = createRecentStore(new MemoryStorage());
  store.addTask({ task_id: "t1", status: "created" });
  store.addTask({ task_id: "t1", status: "running" });
  for (let index = 0; index < 25; index++) store.addTask({ task_id: `t${index + 2}` });
  assert.equal(store.tasks().length, 20);
  assert.equal(store.tasks().some((item) => item.task_id === "t1"), false);
});

test("platform response and usage helpers are deterministic", () => {
  assert.deepEqual(asItems({ items: [{ id: 1 }] }), [{ id: 1 }]);
  const summary = summarizeUsage([{ actual: 12, provider: "mock" }, { actual: 8, provider: "mock", degraded: true }]);
  assert.equal(summary.total, 20);
  assert.equal(summary.degraded, 1);
  assert.equal(summary.providers.size, 1);
  assert.ok(lastDaysRange(7, new Date("2026-08-22T00:00:00Z")).from.startsWith("2026-08-15"));
});
