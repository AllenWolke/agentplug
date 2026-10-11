import { getLanguage, translateUI } from "./localization.js";

export const statusLabels = Object.freeze({
  created: "已创建", pending_dispatch: "待派发", running: "执行中", waiting_review: "待审核",
  archived: "已归档", rejected: "已退回", failed: "失败", failed_precheck: "预检失败", cancelled: "已取消", cancelling: "取消确认中", recovering: "恢复前停止确认中",
  PENDING: "待执行", RUNNING: "执行中", WAITING: "等待中", SUCCEEDED: "已完成", FAILED: "失败", CANCELLED: "已取消", DEAD_LETTER: "死信",
  current: "当前生效", historical: "历史已发布（未生效）", draft: "未发布草稿", canary_previous: "灰度旧版本（部分流量）",
  healthy: "健康", ready: "就绪", degraded: "状态降级", unavailable: "不可用", unknown: "未知", active: "已启用", disabled: "已停用", revoked: "已撤销", approved: "已批准", accepted: "已受理", waiting: "等待中", completed: "已完成", succeeded: "已完成", pending: "待处理", published: "已发布", provisioning: "部署中", inactive: "未启用"
});

export function statusTone(status = "") {
  const value = String(status).toLowerCase();
  if (["archived", "succeeded", "completed", "current", "healthy", "ready", "active", "approved", "published"].includes(value)) return "success";
  if (["failed", "failed_precheck", "dead_letter", "rejected", "disabled", "revoked", "unavailable"].includes(value)) return "danger";
  if (["waiting_review", "waiting", "pending", "pending_dispatch", "created", "draft", "cancelling", "recovering"].includes(value)) return "warning";
  if (["running", "canary_previous"].includes(value)) return "info";
  return "neutral";
}

export function formatStatus(status) { return statusLabels[status] ? translateUI(statusLabels[status]) : status || translateUI("未知"); }
export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(getLanguage(), { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date);
}
export function shortId(value, size = 8) { return value && value.length > size * 2 ? `${value.slice(0, size)}…${value.slice(-4)}` : value || "—"; }
export function escapeHTML(value) { return String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]); }
export function prettyJSON(value) {
  if (value === undefined || value === null || value === "") return "—";
  try { return JSON.stringify(typeof value === "string" ? JSON.parse(value) : value, null, 2); } catch { return String(value); }
}
