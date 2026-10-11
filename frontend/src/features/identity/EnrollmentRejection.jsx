import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useState } from "react";
import { api } from "../../api.js";

export function EnrollmentRejection({ item, onSaved, onClose }) {
  useLanguage();
  const [reason, setReason] = useState("");
  const [plan, setPlan] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const preview = async event => {
    event.preventDefault(); setBusy(true); setError(""); setPlan(null);
    try {
      setPlan(await api.previewEnrollmentRejection({ enrollment_id: item.id, expected_revision: item.revision,
        idempotency_key: crypto.randomUUID(), reason: reason.trim() }));
    } catch (cause) { setError(cause.message); }
    finally { setBusy(false); }
  };
  const commit = async () => {
    setBusy(true); setError("");
    try {
      const receipt = await api.rejectEnrollmentPermission({ ...plan.change, plan_digest: plan.plan_digest, plan_expires_at: plan.plan_expires_at });
      await onSaved(receipt); onClose();
    } catch (cause) { setError(cause.message); if (cause.status === 409) setPlan(null); }
    finally { setBusy(false); }
  };
  return <Localized><section className="card" aria-label="入驻拒绝预览"><div className="card-heading"><h3>拒绝 {item.username} 的入驻申请</h3><button className="button secondary" disabled={busy} onClick={onClose}>关闭</button></div>
    {error && <p role="alert" className="form-error">{error}</p>}
    <form onSubmit={preview}><label>向申请人公开的拒绝理由<textarea required maxLength={500} disabled={busy} value={reason} onChange={event => { setReason(event.target.value); setPlan(null); }}/></label><button className="button secondary" disabled={busy} type="submit">预览拒绝结果</button></form>
    {plan && <div><p>拒绝 {plan.username} 的本次申请，清除申请中的认证材料。申请人可查看拒绝理由。</p><p>{plan.change.reason}</p><button className="button secondary danger" disabled={busy || Date.parse(plan.plan_expires_at) <= Date.now()} onClick={commit}>确认拒绝</button></div>}
  </section></Localized>;
}
