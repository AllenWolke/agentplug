import { formatStatus } from "../../format.js";

const CONTRACT = "cancellation-state/v1";
const PROGRESS = "cancellation-compensation/v1";
const LIMIT = 16384;
const invalid = () => new Error("取消状态证据无法确认，请重新读取运行状态");

// Keep only bounded public metadata. A terminal status, HTTP 200 or Agent
// acknowledgement cannot by itself prove business compensation completed.
export function checkedCancellation(status, value) {
  if (!["cancelling", "cancelled"].includes(status)) {
    if (value !== undefined && value !== null) throw invalid();
    return null;
  }
  if (value === undefined || value === null) return {
    version: CONTRACT,
    disposition: status === "cancelled" ? "historical_unverified" : "pending_unverified"
  };
  if (typeof value !== "object" || Array.isArray(value) || value.version !== CONTRACT) throw invalid();
  const disposition = value.disposition;
  if (["historical_unverified", "pending_unverified"].includes(disposition)) {
    if (status !== (disposition === "historical_unverified" ? "cancelled" : "cancelling") || value.progress != null) throw invalid();
    return { version: CONTRACT, disposition };
  }
  if (!["verified", "in_progress"].includes(disposition)) throw invalid();
  const p = value.progress;
  if (!p || typeof p !== "object" || Array.isArray(p) || p.version !== PROGRESS ||
      typeof p.cancellation_id !== "string" || !/^[0-9a-f]{64}$/.test(p.cancellation_id) ||
      !["stopping", "compensating", "needs_attention", "complete"].includes(p.phase) ||
      typeof p.stop_confirmed !== "boolean") throw invalid();
  const counts = ["total", "compensated", "no_effect", "unresolved", "needs_attention"];
  if (counts.some((key) => !Number.isSafeInteger(p[key]) || p[key] < 0 || p[key] > LIMIT) ||
      p.compensated + p.no_effect + p.unresolved !== p.total || p.needs_attention > p.unresolved ||
      (p.phase === "stopping" ? p.stop_confirmed : !p.stop_confirmed) ||
      (p.phase === "needs_attention") !== (p.needs_attention > 0)) throw invalid();
  if (disposition === "verified") {
    if (status !== "cancelled" || p.phase !== "complete" || p.unresolved !== 0 || !p.stop_confirmed) throw invalid();
  } else if (status !== "cancelling" || p.phase === "complete") throw invalid();
  return { version: CONTRACT, disposition, progress: {
    version: PROGRESS, cancellation_id: p.cancellation_id, phase: p.phase,
    stop_confirmed: p.stop_confirmed, ...Object.fromEntries(counts.map((key) => [key, p[key]]))
  } };
}

export function formatCancellationStatus(status, value) {
  if (status === "cancellation_requested") return "取消请求待确认";
  if (!["cancelling", "cancelled"].includes(status)) return formatStatus(status);
  let view;
  try { view = checkedCancellation(status, value); } catch { return "取消状态待核对"; }
  if (view.disposition === "historical_unverified") return "历史执行已终止，撤销未验证";
  if (view.disposition === "pending_unverified") return "取消处理中：等待停止与撤销确认";
  if (view.disposition === "verified") return "已取消";
  const p = view.progress;
  if (p.phase === "needs_attention") return "取消未完成：需要核对或补偿";
  if (p.phase === "stopping") return "取消处理中：正在停止执行";
  return `取消处理中：正在撤销变更（${p.compensated + p.no_effect}/${p.total}）`;
}
