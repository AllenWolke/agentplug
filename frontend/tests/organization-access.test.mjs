import test from "node:test";
import assert from "node:assert/strict";
import { membershipTargets, grantScopes, delegatedAgentTargets, latestPresets } from "../src/features/identity/organization-access.js";

const app = { scope_type: "application", tenant_id: "company", department_id: "sales", application_id: "area", management_actions: ["membership.manage", "authorization.change"] };
const department = { scope_type: "department", tenant_id: "company", department_id: "sales" };
const admin = { policy_mode: "v2", administration_kind: "department", tenant_id: "company" };

test("department membership and application assignments remain distinct and inside one company", () => {
  assert.deepEqual(membershipTargets(admin, { tenant_id: "company" }, [app, { ...app, tenant_id: "foreign" }]), [department, { scope_type: "application", tenant_id: "company", department_id: "sales", application_id: "area" }]);
  assert.deepEqual(membershipTargets(admin, { tenant_id: "foreign" }, [app]), []);
  assert.deepEqual(membershipTargets(admin, { tenant_id: "company" }, [{ ...department, management_actions: ["membership.manage"] }]), [department]);
  const member = { status: "active", scope: department };
  assert.equal(grantScopes({ memberships: [member] }, { scope_types: ["application"] }, [app])[0].scope.application_id, "area");
  assert.deepEqual(grantScopes({ memberships: [{ ...member, expires_at: "2000-01-01" }] }, { scope_types: ["application"] }, [app]), []);
});

test("an application delegation cannot authorize department membership or unlisted Agents", () => {
  const delegated = { ...admin, administration_kind: "permission", delegations: [{ status: "active", scope: app, management_actions: ["membership.manage", "authorization.change"], resources: ["allowed-agent"] }] };
  assert.equal(membershipTargets(delegated, { tenant_id: "company" }, [app]).length, 1);
  assert.deepEqual(delegatedAgentTargets(delegated, [{ id: "allowed-agent" }, { id: "other-agent" }], app), [{ id: "allowed-agent" }]);
  delegated.delegations[0].expires_at = "2000-01-01";
  assert.deepEqual(delegatedAgentTargets(delegated, [{ id: "allowed-agent" }], app), []);
});

test("the available preset version is explicit without rewriting old assignments", () => {
  const old = { preset_code: "department_admin", preset_version: 1 };
  const next = { ...old, preset_version: 2 };
  assert.deepEqual(latestPresets([old, next]), [next]);
  assert.equal(old.preset_version, 1);
});
