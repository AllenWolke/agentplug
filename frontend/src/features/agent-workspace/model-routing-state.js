const ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const SHA = /^[a-f0-9]{64}$/;

export function checkedModelRouting(value) {
  if (value === undefined) return null; // Compatible with earlier platform versions.
  if (!value || value.version !== "run-model-routing/v1" ||
      !["manual", "automatic"].includes(value.mode) || !Array.isArray(value.decisions) ||
      value.decisions.length > 64 || typeof value.truncated !== "boolean") {
    throw new Error("模型选择状态尚未确认，请重新读取");
  }
  const decisions = value.decisions.map((item) => {
    if (!item || !SHA.test(item.decision_sha256 || "") ||
        !ID.test(item.model_key || "") || !ID.test(item.model_version_id || "") ||
        !ID.test(item.price_version_id || "") || !["simple", "medium", "complex"].includes(item.complexity) ||
        !Number.isSafeInteger(item.estimated_micros) || item.estimated_micros < 0 ||
        !["not_admitted", "running", "failed", "reconcile", "completed"].includes(item.invocation_status) ||
        !Array.isArray(item.reasons) || item.reasons.length > 8 ||
        item.reasons.some((reason) => typeof reason !== "string" || !ID.test(reason)) ||
        item.fallback_attempt !== undefined &&
        (!Number.isSafeInteger(item.fallback_attempt) || item.fallback_attempt < 0 || item.fallback_attempt > 64) ||
        item.previous_decision_sha256 !== undefined && !SHA.test(item.previous_decision_sha256) ||
        item.actual_cost_micros !== undefined &&
        (!Number.isSafeInteger(item.actual_cost_micros) || item.actual_cost_micros < 0 || item.invocation_status !== "completed")) {
      throw new Error("模型调用回执尚未确认，请重新读取");
    }
    return { decision_sha256: item.decision_sha256, model_key: item.model_key,
      model_version_id: item.model_version_id, price_version_id: item.price_version_id,
      complexity: item.complexity, reasons: [...item.reasons], estimated_micros: item.estimated_micros,
      invocation_status: item.invocation_status,
      ...(item.fallback_attempt === undefined ? {} : { fallback_attempt: item.fallback_attempt }),
      ...(item.previous_decision_sha256 === undefined ? {} : { previous_decision_sha256: item.previous_decision_sha256 }),
      ...(item.actual_cost_micros === undefined ? {} : { actual_cost_micros: item.actual_cost_micros }) };
  });
  return { version: value.version, mode: value.mode, decisions, truncated: value.truncated };
}
