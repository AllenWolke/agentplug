function itemsOf(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  return [];
}

// Keep legacy enrollment review isolated from the already-migrated Identity
// access-request workflow. A retired Backend route must not hide the new page.
// 将旧注册审批与已迁移的 Identity Agent 权限申请隔离；旧 Backend 路由失效不能遮蔽新页面。
export async function loadEnrollmentReview(api, status) {
  return itemsOf(await api.userEnrollments({ status, page: 1, page_size: 50 }));
}

// Load only the module-owned catalog and access-request contract here.
// 此处只加载新模块拥有的 Agent 目录与访问申请契约。
export async function loadAgentAccessReview(api, policyMode = "legacy") {
  const [catalog, accessRequests] = await Promise.all([
    api.myAgentCatalog(),
    policyMode === "v2" ? Promise.resolve([]) : api.identityAgentAccessRequests({ status: "pending" })
  ]);
  return { catalog: itemsOf(catalog), accessRequests: itemsOf(accessRequests) };
}
