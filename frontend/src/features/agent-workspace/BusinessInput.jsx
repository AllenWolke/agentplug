import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useState } from "react";
import { exampleFormFields, updateExampleField } from "./example-form.js";

export function BusinessInput({ agentId, presentation, input, onChange, busy }) {
  useLanguage();
  const fields = exampleFormFields(agentId);
  const [advanced, setAdvanced] = useState(!fields.length);
  let value, parseError = "";
  try { value = input.trim() ? JSON.parse(input) : {}; if (!value || Array.isArray(value) || typeof value !== "object") parseError = "输入必须是 JSON 对象。"; }
  catch { parseError = "高级输入含无效 JSON，请修正后再使用表单。"; }
  return <Localized><div className="agent-input">
    <div className="agent-input-heading"><h3>描述你的任务</h3><div className="inline-actions">{presentation.exampleInput && <button type="button" className="text-button" disabled={busy || !!input.trim()} onClick={() => onChange(presentation.exampleInput)}>填入示例</button>}{fields.length > 0 && <button type="button" className="text-button" disabled={busy || advanced && !!parseError} onClick={() => setAdvanced(current => !current)}>{advanced ? "返回业务表单" : "高级输入"}</button>}</div></div>
    {advanced ? <label htmlFor="agent-business-input">业务输入（JSON）<textarea id="agent-business-input" aria-describedby="agent-input-hint" value={input} disabled={busy} onChange={event => onChange(event.target.value)} maxLength={10000} rows={6} spellCheck={false} placeholder={presentation.exampleInput || '{\n  "业务字段": "按智能体协议填写"\n}'}/></label> : <div className="form">{fields.map(field => <label key={field.key} htmlFor={`business-${field.key}`}>{field.label}{field.required && <span className="required-mark">（必填）</span>}{React.createElement(field.multiline ? "textarea" : "input", { id: `business-${field.key}`, name: field.key, value: typeof value?.[field.key] === "string" ? value[field.key] : "", disabled: busy, required: field.required, maxLength: field.multiline ? 6000 : 256, ...(field.multiline ? { rows: 3 } : {}), placeholder: field.hint, onChange: event => onChange(updateExampleField(agentId, input, field.key, event.target.value)) })}</label>)}</div>}
    {parseError && <p className="form-error" role="alert">{parseError}</p>}
    <p className="form-hint" id="agent-input-hint">{fields.length ? "填写任务后即可开始，也可先填入示例体验。" : "按照此智能体提供的字段协议填写。"}示例只生成回答或草稿；代码执行、跨智能体协作等操作需要另外配置和授权。</p>
  </div></Localized>;
}
