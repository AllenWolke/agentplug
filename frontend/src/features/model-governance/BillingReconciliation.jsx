import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useState } from "react";
import { api } from "../../api.js";

// Human decisions resolve accounting only; they never fabricate a model answer.
// 人工决策仅处理计费，绝不伪造模型响应或自动重跑模型。
export function BillingReconciliation() {
  useLanguage();
  const [records, setRecords] = useState([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [outcome, setOutcome] = useState("no_charge");
  const [decisionID, setDecisionID] = useState("");
  const load = async () => {
    const value = await api.modelBillingReconciliations();
    return Array.isArray(value?.items) ? value.items : Array.isArray(value?.data?.items) ? value.data.items : [];
  };
  useEffect(() => {
    let active = true;
    load().then((items) => { if (active) setRecords(items); })
      .catch((reason) => { if (active) setError(reason.message || "对账记录查询失败"); });
    return () => { active = false; };
  }, []);
  const refresh = async () => {
    setBusy(true); setError("");
    try { setRecords(await load()); }
    catch (reason) { setError(reason.message || "对账记录查询失败"); }
    finally { setBusy(false); }
  };
  const select = (record) => {
    setSelected(record); setOutcome("no_charge"); setNotice("");
    // Keep the ID for retries until an accepted response; 重试沿用同一决策 ID。
    setDecisionID(globalThis.crypto.randomUUID());
  };
  const submit = async (event) => {
    event.preventDefault();
    if (!selected || busy) return;
    const form = new FormData(event.currentTarget);
    const integer = (name) => {
      const value = Number(form.get(name));
      if (!Number.isSafeInteger(value) || value < 0) throw new Error("费用和 Token 必须是非负安全整数");
      return value;
    };
    setBusy(true); setError(""); setNotice("");
    try {
      const decision = { id: decisionID, reservation_id: selected.reservation_id,
        outcome, reason: String(form.get("reason") || "").trim(),
        provider_ref: String(form.get("provider_ref") || "").trim() };
      if (outcome === "charged") Object.assign(decision, {
        provider: String(form.get("provider") || "").trim(), model: String(form.get("model") || "").trim(),
        cost_micros: integer("cost_micros"), input_tokens: integer("input_tokens"), output_tokens: integer("output_tokens")
      });
      // Identity is supplied by the trusted BFF, never by the browser.
      // 主体身份由可信 BFF 注入，浏览器不得提交审批人身份。
      await api.decideModelBillingReconciliation({ scope_hash: selected.scope_hash,
        idempotency_key: selected.idempotency_key, fingerprint: selected.fingerprint, decision });
      setSelected(null);
      setNotice("决策已持久化受理，等待后台补偿；受理不等于结算完成。请刷新查看状态。");
    } catch (reason) { setError(reason.message || "决策提交失败；请勿更换决策 ID 盲目重试"); }
    finally { setBusy(false); }
  };
  return <Localized><section className="card">
    <div className="card-heading"><div><h3>模型计费人工对账</h3><p className="form-hint">仅系统/平台管理员可操作。最近最多 100 条；未知结果保留预算，必须核实厂商回执，不能按超时释放。</p></div><button className="button secondary" disabled={busy} onClick={refresh}>刷新对账记录</button></div>
    {error && <div role="alert" className="form-error">{error}</div>}
    {notice && <div role="status" className="success-banner">{notice}</div>}
    <div className="record-list">{records.map((record) => <div key={`${record.scope_hash}:${record.idempotency_key}`}><span><b>{record.tenant_id} / {record.application_id} / {record.agent_id}</b><small>预占 {record.reserve_micros} micros · 状态 {record.state}</small><small>回执决策 {record.decision?.id || "尚未提交"}</small></span>{record.state === "manual" && <button className="button secondary" disabled={busy} onClick={() => select(record)}>核对厂商回执</button>}</div>)}</div>
    {!records.length && !error && <p>暂无对账记录</p>}
    {selected && <form className="form" onSubmit={submit}>
      <p>决策 ID：{decisionID}；费用使用原调用账本币种的微单位。</p>
      <label><span>厂商核实结果</span><select value={outcome} disabled={busy} onChange={(event) => setOutcome(event.target.value)}><option value="no_charge">确认未计费：释放预算后允许重新调用</option><option value="charged">确认已计费：结算但禁止自动重跑</option></select></label>
      <label><span>厂商回执引用（不要填写密钥）</span><input name="provider_ref" required maxLength={256} disabled={busy}/></label>
      <label><span>核实原因</span><textarea name="reason" required maxLength={1024} disabled={busy}/></label>
      {outcome === "charged" && <><input name="provider" aria-label="厂商" required maxLength={128} disabled={busy}/><input name="model" aria-label="模型" required maxLength={128} disabled={busy}/>{["cost_micros", "input_tokens", "output_tokens"].map((name) => <label key={name}><span>{name}</span><input name={name} type="number" min="0" max={Number.MAX_SAFE_INTEGER} step="1" required disabled={busy}/></label>)}</>}
      <label className="checkbox-row"><input type="checkbox" required disabled={busy}/><span>已核实厂商账单；此操作不恢复或生成模型答案</span></label>
      <button className="button primary" disabled={busy}>提交计费决策</button>
      <button type="button" className="button secondary" disabled={busy} onClick={() => setSelected(null)}>取消核对</button>
    </form>}
  </section></Localized>;
}
