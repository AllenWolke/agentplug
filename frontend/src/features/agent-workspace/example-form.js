const definitions = {
  "example-go-operations": [
    { key: "service", label: "服务名称", hint: "例如订单服务、支付网关", required: true },
    { key: "symptom", label: "遇到什么问题？", hint: "描述现象、发生时间和影响", required: true, multiline: true },
    { key: "observations", label: "已有排查信息", hint: "日志、监控或已经尝试的方法（可选）", multiline: true }
  ],
  "example-python-documents": [
    { key: "question", label: "你想了解什么？", hint: "描述需要从知识文档中查找的问题", required: true, multiline: true }
  ],
  "example-java-tickets": [
    { key: "ticket_id", label: "工单编号", hint: "填写需要处理的工单编号", required: true },
    { key: "summary", label: "工单摘要", hint: "用一句话描述问题", required: true },
    { key: "details", label: "补充信息", hint: "客户描述、影响和已知线索（可选）", multiline: true }
  ]
};
export const exampleFormFields = id => definitions[id] || [];
export function exampleInputReady(id, text) {
  if (!text.trim()) return false;
  const fields = exampleFormFields(id);
  if (!fields.length) return true;
  try { const value = JSON.parse(text); return value && !Array.isArray(value) && fields.filter(field => field.required).every(field => typeof value[field.key] === "string" && !!value[field.key].trim()); }
  catch { return false; }
}
export function updateExampleField(id, text, key, value) {
  if (!exampleFormFields(id).some(field => field.key === key)) throw new Error("不支持的业务字段");
  let input;
  try { input = text.trim() ? JSON.parse(text) : {}; } catch { throw new Error("高级输入含无效 JSON，请先修正后再切换到表单。"); }
  if (!input || Array.isArray(input) || typeof input !== "object") throw new Error("高级输入必须是 JSON 对象。");
  // Preserve explicit expert options; never silently enable tool side effects.
  return JSON.stringify({ ...input, [key]: value }, null, 2);
}
