// Build an Installation command from trusted session scope and published Catalog facts.
// 从可信登录会话作用域和已发布 Catalog 事实构造 Installation 命令。
export function applicationInstallationCommand(form, user, definition, version, id) {
  const scope = {
    tenant_id: String(user?.tenant_id || "").trim(),
    department_id: String(user?.department_id || "").trim(),
    application_id: String(user?.application_id || "").trim()
  };
  if (Object.values(scope).some((value) => !value)) {
    throw new Error("当前登录用户缺少租户、部门或应用作用域");
  }
  if (!definition || definition.status !== "published" || !definition.agent_key) {
    throw new Error("只能安装已发布的 Agent Definition");
  }
  if (!version || version.status !== "published" || version.definition_id !== definition.id) {
    throw new Error("请选择该 Definition 下已发布的 Version");
  }
  const displayName = String(form?.display_name || "").trim();
  if (!displayName) throw new Error("应用内显示名称不能为空");
  const deploymentMode = String(form?.deployment_mode || "managed");
  const drainPolicy = String(form?.drain_policy || "wait");
  if (!["managed", "external"].includes(deploymentMode)) throw new Error("不支持的部署模式");
  if (!["wait", "cancel"].includes(drainPolicy)) throw new Error("不支持的排空策略");

  return {
    id,
    ...scope,
    agent_id: definition.agent_key,
    version_id: version.id,
    display_name: displayName,
    deployment_mode: deploymentMode,
    drain_policy: drainPolicy,
    retention_policy_id: String(form?.retention_policy_id || "default").trim(),
    status: "provisioning",
    revision: 1
  };
}
