// Build an application create command from form fields and the authenticated
// session scope. Never accept tenant/department scope from editable form data.
// 使用认证会话作用域构建应用创建命令，不从可编辑表单接受租户/部门范围。
export function applicationCreateCommand(values, user) {
  const tenantId = String(user?.tenant_id || "").trim();
  const departmentId = String(user?.department_id || "").trim();
  const code = String(values?.code || "").trim();
  const name = String(values?.name || "").trim();
  if (!tenantId || !departmentId) throw new Error("当前账号没有完整的租户与部门作用域");
  if (!code || !name) throw new Error("应用编码和名称不能为空");
  return { tenant_id: tenantId, department_id: departmentId, code, name };
}
