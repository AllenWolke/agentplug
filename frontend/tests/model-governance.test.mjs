import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/features/model-governance/ModelGovernance.jsx", import.meta.url), "utf8");

test("model governance page uses only implemented module and Usage contracts", () => {
  for (const api of [
    "api.modelProviders(",
    "api.modelDefinitions(",
    "api.modelDefinitionVersions(",
    "api.modelDeployments(",
    "api.modelPolicies(",
    "api.modelPrices(",
    "api.createModelPrice(",
    "api.approveModelPrice(",
    "api.usageAggregate(",
    "api.usageRuns(",
    "api.usageRunSteps("
  ]) assert.ok(source.includes(api), `expected ${api}`);
  for (const legacy of ["api.modelProfiles(", "api.modelCatalog(", "api.budgetAlerts(", "api.createModelPriceVersion(", "api.putBudget("]) {
    assert.equal(source.includes(legacy), false, `legacy API should not be called: ${legacy}`);
  }
  assert.match(source, /Model Price Version/);
  assert.match(source, /价格版本绑定已批准的 Model Version/);
  assert.match(source, /全局预算 \/ 预算阈值告警：当前未接入/);
});

test("model governance policies and deployments only submit fields implemented by their services", () => {
  assert.match(source, /allowed_providers:/);
  assert.match(source, /allowed_models:/);
  assert.match(source, /allow_external:/);
  assert.doesNotMatch(source, /max_data_class|max_tokens:|max_concurrency:|budget_micros:/);
  assert.match(source, /不直接创建\/更新 Kubernetes 工作负载/);
  assert.match(source, /观测健康由可信服务身份上报/);
  assert.match(source, /pattern="\(service\|k8s\|ref\):\/\/\.\+"/);
  assert.match(source, /EndpointRef 是服务端配置的符号引用，不是直接填写的 URL/);
  assert.match(source, /deployment\.observed_revision/);
  assert.match(source, /管理员页面只读查看/);
  assert.doesNotMatch(source, /api\.updateModelDeploymentHealth\(/);
  assert.doesNotMatch(source, /上报健康|更新健康状态|设置为 Ready/);
});
