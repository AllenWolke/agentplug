import { shortId } from "./format.js";
import { translateUI, interpolateUI } from "./localization.js";
import { agentPresentation } from "./features/agent-workspace/catalog-presentation.js";

// Labels are presentation only. Commands and permission checks keep server codes.
export const actionLabels = Object.freeze({
  "skill.load": "使用技能", "agent.delegate": "发起智能体协作", discover: "查看智能体", run: "运行智能体", cancel: "取消运行", invoke: "调用智能体", resume: "恢复运行", events: "查看运行事件",
  "history.read": "查看会话历史", "history.continue": "继续会话", "history.revise": "修订历史消息", "history.regenerate": "重新生成回答",
  "history.share": "分享会话历史", "history.export": "导出会话历史", "history.delete.request": "申请删除会话历史",
  "business.review": "审核业务事项", "business.content.read": "查看业务内容", "audit.content.read": "查看审计内容", "audit.export": "导出审计记录",
  "knowledge.search": "检索知识库", "tool.invoke": "调用工具", "model.generate": "生成模型回答", "model.embed": "生成向量", "memory.read": "读取记忆", "memory.write": "写入记忆",
  "department.agent_access.manage": "管理部门智能体使用", "organization.manage": "管理组织", "membership.manage": "管理成员关系", "principal.read": "查看账号", "principal.disable": "停用账号",
  "authorization.read": "查看授权", "authorization.change": "办理角色与资源授权", "access_request.decide": "审批权限申请",
  "administrator.appoint": "任命管理员", "delegation.manage": "管理授权委托", "platform.monitor": "查看平台运行状态", "model.configure": "配置模型",
  "catalog.manage": "管理智能体目录", "catalog.requestable.read": "查看可申请的智能体", "agent.develop": "开发智能体", "agent.debug": "调试智能体",
  "evaluation.run": "执行评测", "release.submit": "提交发布申请", "release.approve": "审批发布", "prompt.manage": "管理提示词",
  "tool.manage": "管理工具", "policy.manage": "管理策略", "machine.manage": "管理机器身份", "audit.metadata.read": "查看审计摘要"
});
const resourceLabels = { agent_installation: "智能体", skill: "技能", knowledge: "知识库", tool: "工具", model: "模型", memory: "记忆" };
const roleLabels = { super_admin: "超级管理员", permission_admin: "权限管理员", platform_ops_admin: "平台运维管理员", tenant_admin: "租户管理员", department_admin: "部门管理员", application_admin: "应用管理员", agent_developer: "智能体开发者", operator: "业务操作员", reviewer: "业务审核员", auditor: "审计员", integration_admin: "集成管理员", skill_user: "技能使用者", agent_delegate: "智能体协作发起者" };
const dataLabels = { owner: "本人数据", assigned_task: "指派事项", explicit_set: "明确授权记录", approved_organization: "已授权组织" };
export const actionName = code => actionLabels[code] ? translateUI(actionLabels[code]) : interpolateUI("自定义操作（{{0}}）", [shortId(code, 12)]);
export const resourceTypeName = type => translateUI(resourceLabels[type] || "其他资源");
export const roleName = (role, definitions = []) => {
  const code = typeof role === "object" && role !== null ? role.role_code : role;
  if (code === "tenant_admin" && Number(role?.role_version) === 2) return translateUI("公司管理员");
  if (code === "operator" && Number(role?.role_version) === 2) return translateUI("Agent 使用者");
  return roleLabels[code] ? translateUI(roleLabels[code]) : definitions.find(item => item.role_code === code)?.name || interpolateUI("自定义岗位（{{0}}）", [shortId(code, 10)]);
};
export const dataScopeName = type => translateUI(dataLabels[type] || "自定义数据范围");
export function actionOption(item) { return `${actionName(item.code)}${item.resource_type ? ` · ${resourceTypeName(item.resource_type)}` : ""}${item.sensitive ? translateUI("（敏感操作）") : ""}`; }

export function installationName(item = {}) {
  const named = { ...item, name: item.display_name || item.name };
  const name = agentPresentation(named).name;
  return `${name}${item.semantic_version ? ` · ${item.semantic_version}` : ""}`;
}
export function resourceName(type, id, installations = []) {
  const found = installations.find(item => (item.installation_id || item.id) === id);
  return type === "agent_installation" && found ? installationName(found) : interpolateUI("{{0}}（编号 {{1}}）", [resourceTypeName(type), shortId(id, 10)]);
}
export function scopeName(scope = {}, workspaces = [], user = {}) {
  if (scope.scope_type === "global") return translateUI("全平台");
  const same = (candidate, keys) => keys.every(key => candidate[key] === scope[key]);
  const matches = [...workspaces, user];
  if (scope.application_id) {
    const item = matches.find(value => same(value, ["tenant_id", "department_id", "application_id"]));
    const name = item?.application_name && item.application_name !== scope.application_id ? item.application_name : interpolateUI("应用（编号 {{0}}）", [shortId(scope.application_id, 10)]);
    return scope.resource_id ? interpolateUI("{{0}} · 智能体（编号 {{1}}）", [name, shortId(scope.resource_id, 8)]) : name;
  }
  if (scope.department_id) {
    const item = matches.find(value => same(value, ["tenant_id", "department_id"]));
    return item?.department_name && item.department_name !== scope.department_id ? item.department_name : interpolateUI("部门（编号 {{0}}）", [shortId(scope.department_id, 10)]);
  }
  const item = matches.find(value => same(value, ["tenant_id"]));
  return item?.workspace_name || (item?.tenant_name && item.tenant_name !== scope.tenant_id ? item.tenant_name : scope.tenant_id ? interpolateUI("公司工作空间（编号 {{0}}）", [shortId(scope.tenant_id, 10)]) : translateUI("未指定范围"));
}
export function sourceName(source = "") {
  if (source.startsWith("preset:")) return translateUI("岗位预设授权");
  if (source.startsWith("enrollment:")) return translateUI("入驻审批授权");
  if (source.startsWith("resource-editor:")) return translateUI("管理员独立授权");
  if (source.startsWith("permission-request:")) return translateUI("权限申请审批");
  if (source.startsWith("bootstrap") || source.startsWith("public-development")) return translateUI("初始配置授权");
  return translateUI("明确授权记录");
}
