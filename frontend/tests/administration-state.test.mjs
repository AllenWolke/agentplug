import test from "node:test";
import assert from "node:assert/strict";
import { administrationKind, businessAgentChoices, canRequestOwnPermissions, departmentWorkspace, preferredWorkspaceIDs, workspaceChoices, canAssignDepartmentRoles, isProtectedAdministratorBinding } from "../src/features/identity/administration-state.js";

test("account names and expired or foreign bindings confer no administrative identity", () => {
  const user = { policy_mode: "v2", username: "system.admin", tenant_id: "t", role_bindings: [] };
  assert.equal(administrationKind(user), "");
  assert.equal(canRequestOwnPermissions(user), true);
  user.role_bindings = [{ subject_id: "other", role_code: "super_admin", status: "active" }, { subject_id: user.username, role_code: "permission_admin", status: "active", expires_at: "2000-01-01T00:00:00Z" }];
  assert.equal(administrationKind(user), "");
  user.role_bindings.push({ subject_id: user.username, role_code: "permission_admin", status: "active" });
  assert.equal(administrationKind(user), "permission");
  assert.equal(canRequestOwnPermissions(user), false);
});

test("company administration requires the explicit second version and its own company scope", () => {
  const user = { policy_mode: "v2", username: "owner", tenant_id: "company", capabilities: ["membership.manage", "authorization.change"], role_bindings: [{ subject_id: "owner", role_code: "tenant_admin", role_version: 2, status: "active", scope: { scope_type: "tenant", tenant_id: "company" } }] };
  assert.equal(administrationKind(user), "company");
  assert.equal(canRequestOwnPermissions(user), false);
  assert.equal(canAssignDepartmentRoles(user, { id: "member", tenant_id: "company" }), true);
  assert.equal(canAssignDepartmentRoles(user, { id: "owner", tenant_id: "company" }), false);
  assert.equal(canAssignDepartmentRoles(user, { id: "member", tenant_id: "other" }), false);
  for (const binding of [
    { ...user.role_bindings[0], role_version: 1 },
    { ...user.role_bindings[0], scope: { scope_type: "tenant", tenant_id: "other" } },
    { ...user.role_bindings[0], scope: { scope_type: "department", tenant_id: "company", department_id: "sales" } },
    { ...user.role_bindings[0], expires_at: "2000-01-01" },
  ]) assert.equal(administrationKind({ ...user, role_bindings: [binding] }), "");
  assert.equal(canAssignDepartmentRoles({ ...user, administration_kind: "permission" }, { id: "member", tenant_id: "company" }), false);
});

test("the new company identity uses the protected appointment flow while legacy tenant roles remain ordinary", () => {
  assert.equal(isProtectedAdministratorBinding({ role_code: "tenant_admin", role_version: 2 }), true);
  assert.equal(isProtectedAdministratorBinding({ role_code: "tenant_admin", role_version: 1 }), false);
  assert.equal(isProtectedAdministratorBinding({ role_code: "department_admin", role_version: 2 }), false);
  assert.equal(isProtectedAdministratorBinding({ role_code: "permission_admin", role_version: 1 }), true);
  assert.equal(isProtectedAdministratorBinding(undefined), false);
});

test("administrators choose only explicit server-reviewed management workspaces", () => {
  const a = { scope_type: "application", tenant_id: "t", department_id: "d", application_id: "a" };
  const b = { ...a, application_id: "b" };
  const user = { policy_mode: "v2", tenant_id: "t", administration_kind: "permission" };
  assert.deepEqual(workspaceChoices(user, { application_workspaces: [a, b], administration_workspaces: [b, { ...a, tenant_id: "foreign" }] }), [b]);
  assert.deepEqual(workspaceChoices(user, { application_workspaces: [a, b] }), []);
  assert.deepEqual(workspaceChoices({ ...user, administration_kind: "" }, { application_workspaces: [a], administration_workspaces: [b] }), [a]);
});

test("department managers retain independently granted business contexts without gaining new ones", () => {
  const a = { scope_type: "application", tenant_id: "t", department_id: "managed", application_id: "a" };
  const b = { ...a, department_id: "business", application_id: "b" };
  const user = { policy_mode: "v2", tenant_id: "t", administration_kind: "department" };
  assert.deepEqual(workspaceChoices(user, { administration_workspaces: [a], application_workspaces: [a, b, { ...b, tenant_id: "other" }] }), [a, b]);
  const agents = [{ agent_id: "allowed", access_status: "granted" }, { agent_id: "pending", access_status: "requestable" }];
  assert.deepEqual(businessAgentChoices(user, agents), [agents[0]]);
  assert.deepEqual(businessAgentChoices({ ...user, administration_kind: "company" }, agents), [agents[0]]);
  assert.deepEqual(businessAgentChoices({ ...user, administration_kind: "" }, agents), agents);
  assert.equal(canRequestOwnPermissions(user), false);
});

test("department switching prefers exact active contexts over incidental empty groups", () => {
  const empty = { department_id: "d", application_id: "empty" }, business = { department_id: "d", application_id: "business" };
  const role = { subject_id: "u", status: "active", scope: { tenant_id: "t", application_id: "business" } };
  const user = { username: "u", tenant_id: "t", role_bindings: [role, { ...role, subject_id: "other", scope: { tenant_id: "t", application_id: "foreign" } }, { ...role, expires_at: "2000-01-01", scope: { tenant_id: "t", application_id: "expired" } }] };
  const preferred = preferredWorkspaceIDs(user, { application_workspaces: [{ tenant_id: "t", application_id: "empty" }] });
  assert.deepEqual(preferred, ["business", "empty"]);
  assert.equal(departmentWorkspace([empty, business], "d", "previous-department", preferred), business);
  assert.equal(departmentWorkspace([empty, business], "d", "empty", preferred), empty);
  assert.equal(departmentWorkspace([empty], "d", "previous", preferred), empty);
  assert.equal(departmentWorkspace([empty, business], "outside", "business", preferred), undefined);
});
