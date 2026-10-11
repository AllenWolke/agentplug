import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { batchCounts, batchStorageKey, continueBatchSteps, readBatchKey, saveBatchKey, validateBatchResult } from "./permission-batch.js";
import { agentDisplayName } from "../agent-workspace/catalog-presentation.js";

const labels = { pending: "待办理", blocked: "预览未通过", succeeded: "已完成", failed: "需重新核对", cancelled: "已停止" };
const failures = { CONFLICT_REVIEW_REQUIRED: "预览已过期，或权限状态已变更，请重新核对。", PERMISSION_DENIED: "当前权限或部门范围不再允许此项操作。", INVALID_OR_UNAVAILABLE: "用户、申请或资源当前不可用。" };
const storage = () => { try { return globalThis.sessionStorage; } catch { return null; } };

function itemOverview(item) {
  const change = item.command.authorization;
  if (change?.agent_use) return change.memberships?.length ? "开通 Agent 使用 · 新增部门成员" : "开通 Agent 使用 · 保留已有部门成员关系";
  if (change?.memberships?.length) return change.preset?.preset_code === "department_admin" ? "分配部门 · 部门管理员" : change.revoke_binding_ids?.length ? "分配部门 · 部门用户" : "分配部门 · 保留已有身份";
  const decision = item.command.decision;
  if (decision) return decision.decision === "rejected" ? "整份申请不批准" : `批准 ${item.impact?.approved_items ?? decision.approved_item_ids?.length ?? 0} 项，其余事项不批准`;
  return "岗位与资源权限变更";
}

export function PermissionBatchProgress({ user, kind, plan, onLockedChange, onReset, onChanged, describeItem }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const namespace = batchStorageKey(user, kind);
  const [pending, setPending] = useState(() => readBatchKey(storage(), namespace));
  const [batch, setBatch] = useState(null), [busy, setBusy] = useState(false);
  const [error, setError] = useState(""), [unknown, setUnknown] = useState(false);
  const [notFound, setNotFound] = useState(false), [acknowledged, setAcknowledged] = useState(false);
  const [expired, setExpired] = useState(false);
  const [stopping, setStopping] = useState(false);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  useEffect(() => { onLockedChange?.(Boolean(pending) || busy); }, [pending, busy, onLockedChange]);
  useEffect(() => { setAcknowledged(false); }, [plan]);
  useEffect(() => {
    if (!plan || pending) { setExpired(false); return; }
    const deadline = Date.parse(plan.plan_expires_at);
    const delay = deadline - Date.now();
    setExpired(!Number.isFinite(deadline) || delay <= 0);
    if (!Number.isFinite(deadline) || delay <= 0) return;
    const timer = setTimeout(() => setExpired(true), Math.min(delay, 2147483647));
    return () => clearTimeout(timer);
  }, [plan, pending]);

  const refresh = async key => {
    setBusy(true); setError(""); setNotFound(false);
    try {
      const result = validateBatchResult(await api.permissionBatch(key), key, user, kind);
      if (active.current) { setBatch(result); setUnknown(false); }
    } catch (cause) {
      if (active.current) { setUnknown(true); setNotFound(cause.status === 404); setError(cause.status === 404 ? "未查询到已登记批次。此查询没有提交或继续办理任何权限。" : cause.message || "暂时无法查询批次，请保留原编号。" ); }
    } finally { if (active.current) setBusy(false); }
  };
  // Restore by reading only. Reloading, changing language, or opening this page
  // must never register or continue an authorization batch.
  useEffect(() => { const key = readBatchKey(storage(), namespace); if (key) void refresh(key); }, [namespace]);

  const notify = async result => {
    try { await onChanged?.(result); }
    catch { if (active.current) setError("批次结果已保存，但列表刷新失败，请手动刷新列表。"); }
  };
  const advance = async initial => {
    const result = await continueBatchSteps(api, { key: initial.change.idempotency_key, batch: initial, user, kind,
      isActive: () => active.current, onResult: value => { if (active.current) setBatch(value); } });
    if (active.current) { setBatch(result); await notify(result); }
  };
  const submit = async () => {
    if (busy || pending || !acknowledged || !plan) return;
    if (expired || !Number.isFinite(Date.parse(plan.plan_expires_at)) || Date.parse(plan.plan_expires_at) <= Date.now()) {
      setExpired(true); setError("预览已过期，请重新预览。"); return;
    }
    const key = plan.change.idempotency_key;
    setError(""); setBusy(true);
    try {
      saveBatchKey(storage(), namespace, key);
      setPending(key); setUnknown(false); setNotFound(false);
      const result = validateBatchResult(await api.createPermissionBatch({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at }), key, user, kind);
      if (active.current) { setBatch(result); await advance(result); }
    } catch (cause) {
      if (active.current) { setUnknown(Boolean(readBatchKey(storage(), namespace))); setError(cause.message || "办理结果暂不确定，请查询原批次。"); }
    } finally { if (active.current) setBusy(false); }
  };
  const resume = async () => {
    if (busy || unknown || !batch || !batchCounts(batch.items).pending) return;
    setBusy(true); setError("");
    try { await advance(batch); }
    catch (cause) { if (active.current) { setUnknown(true); setError(cause.message || "办理结果暂不确定，请查询原批次。"); } }
    finally { if (active.current) setBusy(false); }
  };
  const cancel = async () => {
    if (busy || unknown || !stopping || !batch || !batchCounts(batch.items).pending) return;
    setBusy(true); setError("");
    try {
      const result = validateBatchResult(await api.cancelPermissionBatch(pending), pending, user, kind);
      if (active.current) { setBatch(result); setStopping(false); await notify(result); }
    } catch (cause) { if (active.current) { setUnknown(true); setError(cause.message || "停止结果暂不确定，请查询原批次。"); } }
    finally { if (active.current) setBusy(false); }
  };
  const clear = () => {
    if (busy || !notFound && (!batch || unknown || batchCounts(batch.items).pending)) return;
    try {
      storage().removeItem(namespace);
      setPending(""); setBatch(null); setError(""); setUnknown(false); setNotFound(false); setStopping(false); onReset?.();
    } catch { setError("浏览器无法清除已查看的批次编号，请检查会话存储。"); }
  };

  if (!plan && !pending) return null;
  const displayed = batch || (!pending ? plan : null);
  const counts = batchCounts(displayed?.items);
  const summary = displayed?.change?.scope;
  return <Localized><section id={`permission-batch-${kind}`} className="card permission-batch-progress" aria-label="批次办理结果" aria-busy={busy}>
    <div className="card-heading"><h3>{pending ? "批次办理结果" : "核对本次批量变更"}</h3>{summary && <span>{scopeLabel(summary)}</span>}</div>
    <p className="form-hint">每人单独保存结果；已完成项不会重复办理，其他项失败不会撤销已完成的变更。</p>
    {displayed && <div className="batch-summary" role="status"><span>待办理 {counts.pending}</span><span>已完成 {counts.succeeded}</span><span>需核对 {counts.failed + counts.blocked}</span><span>已停止 {counts.cancelled}</span></div>}
    {error && <p className="form-error" role="alert">{error}</p>}
    {unknown && <p className="notice">结果暂不确定。请先查询原批次，不要重新提交或换一个编号。</p>}
    <div className="batch-results">{(displayed?.items || []).map(item => <article key={item.index} className="batch-result-row">
      <div><b>{item.subject_id ? <span data-i18n-preserve>{item.subject_id}</span> : "申请人待核对"}</b><p className="form-hint">{itemOverview(item)}</p>
        {item.impact?.agent_display_name && <p className="form-hint" data-i18n-preserve>{agentDisplayName(item.impact.agent_display_name)}</p>}
        {item.impact && ((item.impact.revoked_binding_ids?.length || 0) + (item.impact.revoked_grant_ids?.length || 0) + (item.impact.revoked_assignment_ids?.length || 0) > 0) && <p className="batch-impact-warning">预览将收回：岗位 {item.impact.revoked_binding_ids?.length || 0} · 资源权限 {item.impact.revoked_grant_ids?.length || 0} · 任务指派 {item.impact.revoked_assignment_ids?.length || 0}</p>}
        {item.failure_code && <p className="form-hint">{failures[item.failure_code] || "此项未完成，请重新核对。"}</p>}
      </div>
      <span className={`badge ${item.status === "succeeded" ? "success" : ["failed", "blocked"].includes(item.status) ? "danger" : ""}`}>{labels[item.status]}</span>
      <details className="batch-result-details"><summary>查看影响</summary><div>{describeItem?.(item)}
        {item.impact && <p className="form-hint">预览：成员调整 {item.impact.changed_memberships} · 新增岗位 {item.impact.added_roles} · 新增资源权限 {item.impact.added_resource_grants}</p>}
        <TechnicalDetails summary="核对收回明细" values={{ "岗位授权编号": item.impact?.revoked_binding_ids, "资源授权编号": item.impact?.revoked_grant_ids, "任务指派编号": item.impact?.revoked_assignment_ids }}/>
      </div></details>
    </article>)}</div>
    {!pending && plan && <><label className="checkbox-field"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} disabled={busy || expired}/><span>我已核对范围、人员及各项影响，确认办理通过预览的事项。</span></label><p className="form-hint">预览未通过的项不会办理。预览过期后，请重新预览。</p>{expired && <p className="notice" role="status">预览已过期，请重新预览。</p>}<button className="button primary" disabled={busy || expired || !acknowledged || !counts.pending || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={submit}>确认并批量办理</button></>}
    {pending && <><div className="inline-actions"><button className="button secondary" disabled={busy} onClick={() => refresh(pending)}>查询原批次</button>{batch && counts.pending > 0 && <><button className="button primary" disabled={busy || unknown} onClick={resume}>继续未办理项</button><button className="button secondary danger" disabled={busy || unknown} onClick={() => setStopping(value => !value)}>停止未办理项</button></>}{(notFound || batch && !counts.pending && !unknown) && <button className="button secondary" disabled={busy} onClick={clear}>{notFound ? "确认未登记，重新核对" : "已查看结果，准备下一批"}</button>}</div>
      {stopping && <div className="notice"><p>停止只影响尚未办理的项，已完成的权限变更会保留。</p><button className="button secondary danger" disabled={busy || unknown} onClick={cancel}>确认停止剩余项</button></div>}
      <TechnicalDetails values={{ "批次查询编号": pending, "批次编号": batch?.batch_id }}/></>}
  </section></Localized>;
}
