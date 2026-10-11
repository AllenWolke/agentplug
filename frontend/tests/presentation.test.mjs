import test from "node:test";

test("company and published tenant roles retain distinct versioned names", () => {
  assert.equal(roleName({ role_code: "tenant_admin", role_version: 2 }), "公司管理员");
  assert.equal(roleName({ role_code: "tenant_admin", role_version: 1 }), "租户管理员");
  assert.equal(roleName("tenant_admin"), "租户管理员");
  assert.equal(roleName({ role_code: "super_admin", role_version: 1 }), "超级管理员");
});
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { actionLabels, actionOption, installationName, scopeName, roleName } from "../src/presentation.js";
import { exampleInputReady, updateExampleField } from "../src/features/agent-workspace/example-form.js";

test("every server permission action has a readable Chinese name", () => {
  const source = readFileSync(new URL("../../platform/internal/identity/permission_policy.go", import.meta.url), "utf8").split("func BuiltinPermissionActions()")[1].split("func BuiltinRoleDefinitions()")[0];
  const codes = [...source.matchAll(/PermissionAction\{Code: "([^"]+)"/g)].map(item => item[1]);
  for (const group of source.matchAll(/for _, code := range \[\]string\{([^}]+)\}/g)) codes.push(...[...group[1].matchAll(/"([^"]+)"/g)].map(item => item[1]));
  assert.ok(codes.length > 40);
  for (const code of codes) assert.match(actionLabels[code] || "", /[\u4e00-\u9fff]/, code);
  const action = Object.freeze({ code: "history.export", resource_type: "agent_installation", sensitive: true });
  assert.equal(actionOption(action), "导出会话历史 · 智能体（敏感操作）");
  assert.equal(action.code, "history.export");
});

test("scope display never borrows a name from another tenant with the same application ID", () => {
  const scope = { tenant_id: "a", department_id: "d", application_id: "app" };
  const wrong = { ...scope, tenant_id: "b", application_name: "其他租户的应用" };
  assert.equal(scopeName(scope, [wrong]), "应用（编号 app）");
  assert.equal(scopeName(scope, [wrong, { ...scope, application_name: "客户服务" }]), "客户服务");
  assert.equal(installationName({ id: "long-installation-path", agent_id: "example-java-tickets" }), "Java 工单助手");
});

test("business forms preserve expert fields without adding privileged operations", () => {
  const initial = JSON.stringify({ question: "旧问题", top_k: 4, notify_me: false, cache_mode: "bypass" });
  const input = JSON.parse(updateExampleField("example-python-documents", initial, "question", "新问题"));
  assert.deepEqual(input, { question: "新问题", top_k: 4, notify_me: false, cache_mode: "bypass" });
  assert.throws(() => updateExampleField("example-python-documents", initial, "collaborate", true));
  assert.throws(() => updateExampleField("example-python-documents", "broken", "question", "新问题"));
  assert.equal(exampleInputReady("example-java-tickets", '{"summary":"已填"}'), false);
  assert.equal(exampleInputReady("example-python-documents", '{"question":"  "}'), false);
  assert.equal(exampleInputReady("example-go-operations", '{"service":"订单服务","symptom":"延迟升高"}'), true);
});
