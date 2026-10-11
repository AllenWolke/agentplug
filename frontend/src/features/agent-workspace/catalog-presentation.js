import { translateUI } from "../../localization.js";

const examples = {
  "example-go-operations": {
    name: "Go 运维诊断助手", description: "根据服务现象与观察信息，生成有依据的诊断和排查建议。",
    input: { service: "example-service", symptom: "请求延迟升高，如何进行只读排查？", observations: "未发现明确的错误日志。" }
  },
  "example-python-documents": {
    name: "Python 文档问答助手", description: "检索知识文档，生成带来源引用的回答。",
    input: { question: "文档增量更新如何保持一致性？", top_k: 3, cache_mode: "use" }
  },
  "example-java-tickets": {
    name: "Java 工单助手", description: "根据工单摘要和补充信息，生成回复草稿与处理建议。",
    input: { ticket_id: "UI-DEMO-001", summary: "如何排查服务响应变慢？", details: "请提供只读排查建议。" }
  }
};

// Catalog provides identity and permissions; routing belongs to the console.
// Do not depend on an optional URL, or navigate to a URL supplied by an Agent.
export function agentWorkspacePath(agent) {
  return `/workspace/agent/${encodeURIComponent(agent.agent_id)}`;
}

// Some persisted receipts carry the demo's stable key as its display name.
// Localize those known demo keys while preserving actual custom business names.
export function agentDisplayName(name) {
  return examples[name] ? translateUI(examples[name].name) : name;
}

export function agentPresentation(agent) {
  const example = examples[agent?.agent_id];
  return {
    name: example ? translateUI(example.name) : (agent?.name && agent.name !== agent.agent_id && !/[\\/]/.test(agent.name) ? agent.name : translateUI("未命名智能体")),
    description: agent?.description || translateUI(example?.description || "使用当前应用中已发布的 Agent。"),
    exampleInput: example ? JSON.stringify(Object.fromEntries(Object.entries(example.input).map(([key, value]) => [key, typeof value === "string" ? translateUI(value) : value])), null, 2) : ""
  };
}
