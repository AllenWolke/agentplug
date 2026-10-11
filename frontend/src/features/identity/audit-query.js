export function auditMetadataQuery(query, page = 1) {
  const scopeType = query.scope_type || "application";
  if (!["global", "tenant", "department", "application"].includes(scopeType)) throw new Error("请选择有效的审计范围");
  const result = { scope_type: scopeType, page, page_size: 20 };
  const fields = scopeType === "global" ? [] : scopeType === "tenant" ? ["tenant_id"] : scopeType === "department" ? ["tenant_id", "department_id"] : ["tenant_id", "department_id", "application_id"];
  for (const field of fields) {
    const value = String(query[field] || "").trim();
    if (!value) throw new Error("请填写审计范围所需的组织 ID");
    result[field] = value;
  }
  for (const field of ["task_id", "trace_id"]) {
    const value = String(query[field] || "").trim();
    if (value) result[field] = value;
  }
  return result;
}
