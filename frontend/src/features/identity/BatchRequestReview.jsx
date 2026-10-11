import React, { useEffect, useState } from "react";
import { api } from "../../api.js";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails, useScopeName } from "../../components/DisplayNames.jsx";
import { basicRequestedItems, commonRequestScope, decisionBatchCommand, duplicateRequestSubjects, loadBatchProfiles } from "./permission-batch.js";
import { PermissionBatchProgress } from "./PermissionBatchProgress.jsx";

export function BatchRequestReview({ user, requests, label, onLockedChange, onSaved, onClear }) {
  useLanguage();
  const scopeLabel = useScopeName();
  const [approved, setApproved] = useState({}), [mode, setMode] = useState("approve"), [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null), [busy, setBusy] = useState(false), [locked, setLocked] = useState(false), [error, setError] = useState("");
  const commonScope = commonRequestScope(requests);
  const duplicates = duplicateRequestSubjects(requests);
  const ready = commonScope && !duplicates.length && reason.trim() && (mode === "reject" || requests.every(item => approved[item.id]?.length));
  useEffect(() => { setPlan(null); }, [requests]);
  useEffect(() => { onLockedChange?.(locked || busy); }, [locked, busy, onLockedChange]);
  const change = (id, values) => { setApproved(current => ({ ...current, [id]: values })); setPlan(null); };
  const basic = () => {
    setApproved(current => ({ ...current, ...Object.fromEntries(requests.map(item => [item.id, [...new Set([...(current[item.id] || []), ...basicRequestedItems(item)])]])) }));
    setPlan(null);
  };
  const preview = async event => {
    event.preventDefault(); if (!ready || busy || locked) return;
    setBusy(true); setError(""); setPlan(null);
    try {
      const profiles = await loadBatchProfiles(api, requests.map(item => item.subject_id));
      setPlan(await api.previewPermissionBatch(decisionBatchCommand({ user, requests, profiles, approved, mode, reason, key: crypto.randomUUID() })));
    } catch (cause) { setError(cause.message || "无法生成批量审批预览。"); }
    finally { setBusy(false); }
  };
  const reset = () => { setPlan(null); setApproved({}); setReason(""); setMode("approve"); setError(""); onClear?.(); };
  return <Localized><>
    {requests.length > 0 && !locked && <section id="batch-request-review" className="card batch-request-review" aria-label="批量审批申请">
      <div className="card-heading"><h3>批量审批申请</h3><span>已选 {requests.length} 份申请</span></div>
      <p>统一填写办理原因，按申请核对批准事项。未勾选事项将不获批准。</p>
      {!commonScope && <p className="form-error" role="alert">所选申请不属于同一公司，请分批办理。</p>}
      {duplicates.length > 0 && <p className="notice">同一用户有多份申请，请每批保留该用户一份。办理后刷新其余申请，再预览下一批。</p>}
      {commonScope && <p className="form-hint">共同办理范围：{scopeLabel(commonScope)}</p>}
      <form className="form" onSubmit={preview}><fieldset disabled={busy}>
        <label>办理方式<select value={mode} onChange={event => { setMode(event.target.value); setPlan(null); }}><option value="approve">按所选事项批准</option><option value="reject">全部申请不批准</option></select></label>
        {mode === "approve" ? <>
          <div className="inline-actions"><button type="button" className="button secondary" onClick={basic}>选择申请中的基础使用事项</button><button type="button" className="text-button" onClick={() => { setApproved({}); setPlan(null); }}>清空批准事项</button></div>
          <p className="form-hint">快捷选择只包含申请中的业务操作员和基础会话操作；独立资源、分享、导出及管理权限需单独核对。</p>
          <div className="batch-review-options">{requests.map(request => <details key={request.id} className="batch-review-request"><summary><b data-i18n-preserve>{request.subject_id}</b><span>已选 {approved[request.id]?.length || 0} / {request.items.length} 项</span></summary>
            <p data-i18n-preserve>{request.reason}</p>
            {request.items.map(item => <div key={item.id} className="batch-request-option"><label className="checkbox-field"><input type="checkbox" checked={approved[request.id]?.includes(item.id) || false} onChange={event => change(request.id, event.target.checked ? [...(approved[request.id] || []), item.id] : (approved[request.id] || []).filter(id => id !== item.id))}/><span>{label(item)}</span></label>
              <TechnicalDetails values={{ "完整事项范围": item.scope, "资源编号": item.resource_id, "安装编号": item.installation_id, "数据范围": item.data_scope, "开始时间": item.starts_at, "到期时间": item.expires_at }}/>
            </div>)}
          </details>)}</div>
          {requests.some(item => !approved[item.id]?.length) && <p className="form-hint">每份批准申请至少选择一项；需要整份拒绝的申请请另分一批。</p>}
        </> : <p className="notice">所选申请的全部事项将不获批准，不会新增任何权限。请在下方说明原因。</p>}
        <label>共同办理原因<textarea required maxLength={1000} value={reason} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label>
        <button className="button primary" disabled={busy || !ready} type="submit">预览每份申请的结果</button>
      </fieldset></form>
      {error && <p className="form-error" role="alert">{error}</p>}
    </section>}
    <PermissionBatchProgress user={user} kind="decision" plan={plan} onLockedChange={setLocked} onReset={reset} onChanged={onSaved} describeItem={item => <>
      <p className="form-hint">{item.command.decision?.decision === "rejected" ? "整份申请不批准" : `批准 ${item.command.decision?.approved_item_ids?.length || 0} 项，其余事项不批准`}</p>
      <TechnicalDetails values={{ "申请编号": item.command.decision?.request_id, "批准事项编号": item.command.decision?.approved_item_ids }}/>
    </>}/>
  </></Localized>;
}
