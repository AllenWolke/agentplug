import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/features/evaluation-workspace/EvaluationWorkspace.jsx", import.meta.url), "utf8");

test("evaluation workspace uses the module resource DTO and avoids legacy API fallback", () => {
  assert.match(source, /api\.evaluationProductDatasets/);
  assert.match(source, /api\.evaluationProductSuites/);
  assert.match(source, /api\.evaluationProductMetrics/);
  assert.match(source, /api\.evaluationProductRuns/);
  assert.match(source, /api\.evaluationProductEvidence/);
  assert.match(source, /normalizeResource\(resource\)/);
  assert.doesNotMatch(source, /evaluationDatasetsV2|evaluationSuites\(|createEvaluationRunV2|api\.evaluationEvidence/);
});

test("evaluation UI derives review identity from the authenticated session and applies SoD guards", () => {
  assert.match(source, /api\.me\(\)/);
  assert.match(source, /dataset\.created_by === currentPrincipalID/);
  assert.match(source, /selectedEvidenceRun\.created_by === currentPrincipalID/);
  assert.doesNotMatch(source, /name="reviewer_id"|name="submitter_id"/);
  assert.match(source, /expected_revision: dataset\.revision/);
});

test("evaluation UI never treats the browser as an evaluator or fabricates evidence", () => {
  assert.match(source, /createEvaluationProductRun/);
  assert.match(source, /EVALUATOR_UNAVAILABLE/);
  assert.match(source, /Browser cannot create Evidence|浏览器不能创建 Evidence/);
  assert.doesNotMatch(source, /createEvaluationProductEvidence|publishEvaluationProductEvidence/);
});

test("evaluation Run submission is fail-closed when Dispatcher availability is false or unknown", () => {
  assert.match(source, /api\.evaluationProductAvailability\(\)/);
  assert.match(source, /const evaluatorCanRun = evaluatorAvailability\.configured === true && evaluatorAvailability\.state === "configured"/);
  assert.match(source, /typeof availability\.configured !== "boolean"/);
  assert.match(source, /state: "unknown", reason_code: "EVALUATOR_UNAVAILABLE"/);
  assert.match(source, /disabled=\{busy \|\| !evaluatorCanRun \|\| !suites\.length\}/);
  assert.match(source, /if \(!evaluatorCanRun\) throw new Error\("EVALUATOR_UNAVAILABLE:/);
  assert.match(source, /当前未配置兼容 Evaluation Product 契约的真实 Dispatcher\/Runner，已禁用 Run 提交/);
  assert.match(source, /无法读取或验证 Dispatcher 可用性；状态按未知处理，Run 提交保持禁用/);
  assert.match(source, /此状态只表示可接收执行请求，不代表评测已运行或通过/);
});

test("Metric Registry exposes the pinned isolated plugin contract and kind-specific formulas", () => {
  assert.match(source, /metricFormulaExamples/);
  assert.match(source, /input_relevant_field/);
  assert.match(source, /output_actual_field/);
  assert.match(source, /output_claims_field/);
  assert.match(source, /metric\.plugin_id = String\(form\.get\("plugin_id"\)\)\.trim\(\)/);
  assert.match(source, /metric\.plugin_version = String\(form\.get\("plugin_version"\)\)\.trim\(\)/);
  assert.match(source, /metric\.plugin_digest = String\(form\.get\("plugin_digest"\)\)\.trim\(\)/);
  assert.match(source, /metricKind === "custom_deterministic"/);
  assert.match(source, /pattern="\[A-Fa-f0-9\]\{64\}"/);
  assert.match(source, /form\.get\("plugin_id"\)/);
});
