// Resolve the immutable version exposed by the authenticated application catalog.
// 从已认证应用目录解析不可变版本；调用方不能自行猜测或回退到旧版本 ID。
export function publishedAgentVersion(items, agentID) {
  const agent = Array.isArray(items) ? items.find((item) => item.agent_id === agentID) : null;
  if (!agent || agent.access_status !== "granted") {
    throw new Error("当前用户没有该 Agent 的运行授权，请刷新目录或联系管理员。");
  }
  const versionID = typeof agent.version_id === "string" ? agent.version_id.trim() : "";
  if (!versionID) {
    throw new Error("已授权 Agent 未返回当前发布版本，无法创建会话；请联系管理员检查 Catalog 发布状态。");
  }
  return versionID;
}
