class ApiError extends Error {
  constructor(d, {
    status: o = 0,
    code: p = "NETWORK",
    traceId: u = "",
    details: h = null
  } = {}) {
    super(d), this.name = "ApiError", this.status = o, this.code = String(p), this.traceId = u, this.details = h;
  }
}
function toQuery(i = {}) {
  const d = new URLSearchParams();
  for (const [p, u] of Object.entries(i)) u !== "" && u !== void 0 && u !== null && d.set(p, String(u));
  const o = d.toString();
  return o ? `?${o}` : "";
}
async function parseResponse(i, d = !0) {
  const p = (i.headers.get("content-type") || "").includes("application/json") ? await i.json() : await i.text();
  if (!i.ok) {
    const u = p?.code ?? p?.error?.code ?? i.status,
      h = typeof p?.message == "string" ? p.message : typeof p?.error?.message == "string" ? p.error.message : `请求失败 (${i.status}, ${u})`;
    throw new ApiError(h, {
      status: i.status,
      code: u,
      traceId: p?.trace_id || "",
      details: p
    });
  }
  if (!d) return p;
  if (String(p?.code) !== "0") throw new ApiError(p?.message || "服务返回失败", {
    status: i.status,
    code: p?.code,
    traceId: p?.trace_id || "",
    details: p
  });
  return p.data;
}
function parseSSEChunk(i) {
  const d = [],
    o = i.replace(/\r\n/g, `
`).split(`

`),
    p = o.pop() ?? "";
  for (const u of o) {
    if (u.length > MAX_SSE_REMAINDER_CHARS) {
      throw new ApiError("事件数据块过大", { code: "EVENT_FRAME_TOO_LARGE" });
    }
    if (!u.trim()) continue;
    const h = {
        id: "",
        type: "message",
        data: null
      },
      y = [];
    for (const a of u.split(`
`)) a.startsWith("id:") ? h.id = a.slice(3).trim() : a.startsWith("event:") ? h.type = a.slice(6).trim() : a.startsWith("data:") && y.push(a.slice(5).trimStart());
    const _ = y.join(`
`);
    try {
      h.data = _ ? JSON.parse(_) : null;
    } catch {
      h.data = _;
    }
    d.push(h);
  }
  return {
    events: d,
    remainder: p
  };
}
const MAX_SSE_REMAINDER_CHARS = 64 * 1024;
const MAX_AGENT_EVENT_CURSOR_DECIMAL = "9007199254740991";
function validateEventCursor(cursor) {
  if (typeof cursor !== "string" || !/^\d+$/.test(cursor)) {
    throw new ApiError("事件游标必须是十进制字符串", { code: "REQUEST_INVALID" });
  }
  const normalized = cursor.replace(/^0+(?=\d)/, "");
  if (normalized.length > MAX_AGENT_EVENT_CURSOR_DECIMAL.length ||
      (normalized.length === MAX_AGENT_EVENT_CURSOR_DECIMAL.length && normalized > MAX_AGENT_EVENT_CURSOR_DECIMAL)) {
    throw new ApiError("事件游标超出范围", { code: "REQUEST_INVALID" });
  }
  return cursor;
}
function createApiClient({
  fetchImpl: d = globalThis.fetch,
  refreshLocks = globalThis.navigator?.locks
} = {}) {
  // Only retry the gateway's rejection before forwarding. Business failures
  // never trigger replay, and concurrent requests share one refresh operation.
  let pendingRefresh = null;
  async function authenticatedFetch(url, options) {
    const response = await d(url, options);
    if (response.status !== 401 || response.headers.get("X-Authentication-Error") !== "access_token_invalid") return response;
    if (!pendingRefresh) {
      const renew = async () => (await d("/auth/refresh", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" } })).ok;
      // HttpOnly cookies are shared by tabs. Serialize rotation across the
      // origin, then check whether the preceding tab already renewed access.
      // Neither a token nor a password enters browser storage or messaging.
      pendingRefresh = (refreshLocks?.request
        ? refreshLocks.request("agentplug-auth-refresh", async () => {
            const current = await d("/auth/me", { credentials: "same-origin", cache: "no-store" });
            if (current.ok) return true;
            if (current.status !== 401 || current.headers.get("X-Authentication-Error") !== "access_token_invalid") return false;
            return renew();
          })
        : renew())
        .finally(() => { pendingRefresh = null; });
    }
    if (!await pendingRefresh) return response;
    return d(url, options);
  }
  async function request(a, {
    method: f = "GET",
    body: j,
    query: w,
    headers: v = {},
    signal: D,
    envelope: I = !0
  } = {}) {
    if (!a.startsWith("/auth/") && !a.startsWith("/ops/")) {
      throw new ApiError("旧版非模块 API 路径已退役");
    }
    let k;
    try {
      k = await authenticatedFetch(`${a}${toQuery(w)}`, {
        method: f,
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": crypto.randomUUID(),
          ...v
        },
        body: j === void 0 ? void 0 : JSON.stringify(j),
        signal: D
      });
    } catch (q) {
      throw q?.name === "AbortError" ? q : new ApiError("无法连接 LexAgent 服务", {
        details: q
      });
    }
    return parseResponse(k, I);
  }
  async function readEventStream(a, f, j, { stopOnStreamError = false } = {}) {
    if (!a.startsWith("/api/modules/")) {
      throw new ApiError("事件流必须通过模块网关访问");
    }
    const v = await authenticatedFetch(a, {
        credentials: "same-origin",
        headers: {
          "X-Request-ID": crypto.randomUUID()
        },
        signal: j
      });
    if (!v.ok) return parseResponse(v);
    if (!v.body) throw new ApiError("浏览器不支持流式事件", {
      status: v.status
    });
    const reader = v.body.getReader();
    const decoder = new TextDecoder();
    let remainder = "";
    let reachedEnd = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        remainder += decoder.decode(value || new Uint8Array(), { stream: !done });
        const parsed = parseSSEChunk(remainder);
        remainder = parsed.remainder;
        if (remainder.length > MAX_SSE_REMAINDER_CHARS) {
          throw new ApiError("事件数据块过大", { code: "EVENT_FRAME_TOO_LARGE" });
        }
        if (done && remainder.length > 0) {
          throw new ApiError("事件流帧不完整", { code: "EVENT_FRAME_INVALID" });
        }
        let stop = false;
        for (const event of parsed.events) {
          f(event);
          if (stopOnStreamError && event.type === "stream_error") {
            stop = true;
            break;
          }
        }
        if (done) {
          reachedEnd = true;
          break;
        }
        if (stop) break;
      }
    } finally {
      if (!reachedEnd) {
        try { await reader.cancel(); } catch {}
      }
      reader.releaseLock();
    }
  }
  async function requestPlatformModule(a, f, {
    method: j = "GET",
    body: w,
    query: v,
    headers: D = {},
    signal: I
  } = {}) {
    let A;
    try {
      A = await authenticatedFetch(`/api/modules/${a}${f}${toQuery(v)}`, {
        method: j,
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": crypto.randomUUID(),
          ...D
        },
        body: w === void 0 ? void 0 : JSON.stringify(w),
        signal: I
      });
    } catch (k) {
      throw k?.name === "AbortError" ? k : new ApiError("无法连接平台模块", {
        details: k
      });
    }
    return parseResponse(A, !1);
  }
  async function requestConversationModule(a, f = {}) {
    return requestPlatformModule("conversation", a, f);
  }
  function withResourceDefaults(a = {}) {
    return {
      ...a,
      id: a.id || crypto.randomUUID(),
      status: a.status || "active",
      revision: a.revision || 1
    };
  }
  return {
    login: (a, f) => request("/auth/login", {
      method: "POST",
      body: {
        username: a,
        password: f
      },
      envelope: !1
    }),
    register: a => request("/auth/register", {
      method: "POST",
      body: a,
      envelope: !1
    }),
    registrationAgentCatalog: () => request("/auth/registration-agent-catalog", {
      envelope: !1
    }),
    verifyRegistration: (a, f, j) => request(`/auth/registrations/${encodeURIComponent(a)}/verify-contact`, {
      method: "POST",
      headers: {
        "X-Registration-Token": f
      },
      body: {
        code: j
      },
      envelope: !1
    }),
    registrationStatus: (a, f) => request(`/auth/registrations/${encodeURIComponent(a)}/status`, {
      headers: {
        "X-Registration-Token": f
      },
      envelope: !1
    }),
    withdrawRegistration: (a, f, j) => request(`/auth/registrations/${encodeURIComponent(a)}/withdraw`, {
      method: "POST",
      headers: {
        "X-Registration-Token": f
      },
      body: {
        expected_revision: j
      },
      envelope: !1
    }),
    me: () => request("/auth/me", {
      envelope: !1
    }),
    switchWorkspace: async target => {
      const change = async () => {
        const current = await d("/auth/me", { credentials: "same-origin", cache: "no-store" });
        if (current.status === 401 && current.headers.get("X-Authentication-Error") === "access_token_invalid") {
          await parseResponse(await d("/auth/refresh", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" } }), false);
        } else if (!current.ok) await parseResponse(current, false);
        return parseResponse(await d("/auth/workspace", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(target) }), false);
      };
      return refreshLocks?.request ? refreshLocks.request("agentplug-auth-refresh", change) : change();
    },
    logout: () => request("/auth/logout", {
      method: "POST",
      body: {},
      envelope: !1
    }),
    opsStatus: () => request("/ops/status", {
      envelope: !1
    }),
    taskEvents: (a, f, j) => readEventStream(`/api/modules/execution/platform/runs/${encodeURIComponent(a)}/events`, f, j),
    agentTaskEvents: (runID, callback, signal, afterSeq = "0") => {
      const cursor = validateEventCursor(afterSeq);
      return readEventStream(
        `/api/modules/execution/platform/runs/${encodeURIComponent(runID)}/agent-events?after_seq=${encodeURIComponent(cursor)}`,
        callback,
        signal,
        { stopOnStreamError: true }
      );
    },
    pendingToolOperation: (runID, pendingKey) => requestPlatformModule("tool-approvals", "/pending", {
      method: "POST",
      body: { operation: { run_id: runID, pending_key: pendingKey } }
    }),
    previewToolApproval: operation => requestPlatformModule("tool-approvals", "/preview", { method: "POST", body: { operation } }),
    toolApprovalStepUp: command => requestPlatformModule("tool-approvals", "/step-up", { method: "POST", body: command }),
    approveToolOperation: command => requestPlatformModule("tool-approvals", "/approve", { method: "POST", body: command }),
    revokeToolOperation: command => requestPlatformModule("tool-approvals", "/revoke", { method: "POST", body: command }),
    resumeApprovedToolOperation: command => requestPlatformModule("tool-approvals", "/resume", { method: "POST", body: command }),
    inspectSkill: command => requestPlatformModule("skills", "/inspect", { method: "POST", body: command }),
    registerSkill: (bundle, namespace) => requestPlatformModule("skills", "/register", { method: "POST", body: { bundle, ...(namespace ? { namespace } : {}) } }),
    reviewSkill: command => requestPlatformModule("skills", "/review", { method: "POST", body: command }),
    publishSkill: command => requestPlatformModule("skills", "/publish", { method: "POST", body: command }),
    runReviewSnapshot: a => requestPlatformModule("execution", `/platform/runs/${encodeURIComponent(a)}/review`),
    executionRunStatus: (runID, signal) => requestPlatformModule("execution", `/platform/runs/${encodeURIComponent(runID)}`, { signal }),
    decideRunReview: (a, decision, comment = "") => requestPlatformModule("execution", `/platform/runs/${encodeURIComponent(a)}/resume`, {
      method: "POST", body: { decision, comment }
    }),
    cancelTask: (a, f = "operator cancelled") => requestPlatformModule("execution", `/platform/runs/${encodeURIComponent(a)}/cancel`, {
      method: "POST",
      body: {
        reason: f
      }
    }),
    audits: a => requestPlatformModule("audit", "/events", {
      query: a
    }),
    runtimeAuditSteps: query => requestPlatformModule("audit", "/runtime-steps", { query }),
    auditEventPermissions: id => requestPlatformModule("audit", `/events/${encodeURIComponent(id)}/permissions`),
    auditEventContent: id => requestPlatformModule("audit", `/events/${encodeURIComponent(id)}/content`),
    exportAuditEvents: ids => requestPlatformModule("audit", "/exports", { method: "POST", body: { event_ids: ids } }),
    tenants: () => requestPlatformModule("identity", "/tenants", {
      query: {
        page: 1,
        page_size: 100
      }
    }),
    createTenant: a => requestPlatformModule("identity", "/tenants", {
      method: "POST",
      body: withResourceDefaults(a)
    }),
    departments: (a = "") => requestPlatformModule("identity", "/departments", {
      query: {
        tenant_id: a,
        page: 1,
        page_size: 100
      }
    }),
    createDepartment: a => requestPlatformModule("identity", "/departments", {
      method: "POST",
      body: withResourceDefaults(a)
    }),
    departmentPage: query => requestPlatformModule("identity", "/departments", { query }),
    applications: (a = {}) => requestPlatformModule("identity", "/applications", {
      query: {
        page: 1,
        page_size: 100,
        ...a
      }
    }),
    createApplication: a => requestPlatformModule("identity", "/applications", {
      method: "POST",
      body: withResourceDefaults(a)
    }),
    disableApplication: (a, f, j) => requestPlatformModule("identity", `/applications/${encodeURIComponent(a)}/disable`, {
      method: "POST",
      query: {
        department_id: f
      },
      body: {
        expected_revision: j
      }
    }),
    identityGrants: (a = {}) => requestPlatformModule("identity", "/grants", {
      query: a
    }),
    identityPrincipals: (a = {}) => requestPlatformModule("identity", "/principals", {
      query: a
    }),
	identityPermissions: () => requestPlatformModule("identity", "/me/permissions"),
	notificationInbox: () => requestPlatformModule("notification", "/inbox?limit=100"),
	identityExplainPermission: query => requestPlatformModule("identity", "/permissions:explain", { method: "POST", body: query }),
	identityWorkspaces: () => requestPlatformModule("identity", "/me/workspaces"),
	identityMembershipCandidates: query => requestPlatformModule("identity", "/membership-candidates", { query }),
	identityPresets: () => requestPlatformModule("identity", "/identity-presets"),
	identityAccessProfile: (id, principalType = "user") => requestPlatformModule("identity", `/principals/${encodeURIComponent(id)}/access-profile${principalType === "user" ? "" : `?principal_type=${encodeURIComponent(principalType)}`}`),
	previewIdentityAuthorization: command => requestPlatformModule("identity", "/authorization-changes:preview", { method: "POST", body: command }),
	commitIdentityAuthorization: command => requestPlatformModule("identity", "/authorization-changes", { method: "POST", body: command }),
	previewIdentityMembership: command => requestPlatformModule("identity", "/memberships:preview", { method: "POST", body: command }),
	changeIdentityMembership: command => requestPlatformModule("identity", "/memberships:change", { method: "POST", body: command }),
	previewPermissionPrincipal: command => requestPlatformModule("identity", "/principals:preview", { method: "POST", body: command }),
	createPermissionPrincipal: command => requestPlatformModule("identity", "/principals:create", { method: "POST", body: command }),
	previewEnrollmentPermission: command => requestPlatformModule("identity", "/enrollments:preview-approval", { method: "POST", body: command }),
	approveEnrollmentPermission: command => requestPlatformModule("identity", "/enrollments:approve", { method: "POST", body: command }),
	previewEnrollmentRejection: command => requestPlatformModule("identity", "/enrollments:preview-rejection", { method: "POST", body: command }),
	rejectEnrollmentPermission: command => requestPlatformModule("identity", "/enrollments:reject", { method: "POST", body: command }),
	identityRoleDefinitions: () => requestPlatformModule("identity", "/role-definitions"),
	identityPermissionActions: () => requestPlatformModule("identity", "/permission-actions"),
	permissionRequests: query => requestPlatformModule("identity", "/permission-requests", { query }),
	createPermissionRequest: command => requestPlatformModule("identity", "/permission-requests", { method: "POST", body: command }),
	withdrawPermissionRequest: command => requestPlatformModule("identity", "/permission-requests:withdraw", { method: "POST", body: command }),
	previewPermissionRequestDecision: command => requestPlatformModule("identity", "/permission-requests:preview-decision", { method: "POST", body: command }),
	decidePermissionRequest: command => requestPlatformModule("identity", "/permission-requests:decide", { method: "POST", body: command }),
	previewPermissionBatch: command => requestPlatformModule("identity", "/permission-batches:preview", { method: "POST", body: command }),
	createPermissionBatch: command => requestPlatformModule("identity", "/permission-batches", { method: "POST", body: command }),
	permissionBatch: key => requestPlatformModule("identity", `/permission-batches/${encodeURIComponent(key)}`),
	continuePermissionBatch: key => requestPlatformModule("identity", `/permission-batches/${encodeURIComponent(key)}:continue`, { method: "POST", body: {} }),
	cancelPermissionBatch: key => requestPlatformModule("identity", `/permission-batches/${encodeURIComponent(key)}:cancel`, { method: "POST", body: {} }),
	identityStepUp: input => requestPlatformModule("identity", "/step-up", { method: "POST", body: input }),
	identityStepUpMethod: () => request("/auth/step-up/method", { envelope: false }),
	beginOIDCStepUp: input => request("/auth/step-up/oidc/start", { method: "POST", body: input, envelope: false }),
	previewAdministratorAppointment: command => requestPlatformModule("identity", "/administrators:preview", { method: "POST", body: command }),
	appointIdentityAdministrator: command => requestPlatformModule("identity", "/administrators:appoint", { method: "POST", body: command }),
	previewIdentityDelegation: command => requestPlatformModule("identity", "/delegations:preview", { method: "POST", body: command }),
	changeIdentityDelegation: command => requestPlatformModule("identity", "/delegations", { method: "POST", body: command }),
	departmentAgentPolicy: query => requestPlatformModule("identity", "/department-agent-policy", { query }),
	identityAgentUsePackage: query => requestPlatformModule("identity", "/agent-use-package", { query }),
	previewDepartmentAgentChange: command => requestPlatformModule("identity", "/department-agent-changes:preview", { method: "POST", body: command }),
	commitDepartmentAgentChange: command => requestPlatformModule("identity", "/department-agent-changes", { method: "POST", body: command }),
	departmentAgentChangeReceipt: key => requestPlatformModule("identity", `/department-agent-changes/${encodeURIComponent(key)}`),
    createIdentityPrincipal: a => requestPlatformModule("identity", "/principals", {
      method: "POST",
      body: a
    }),
    disableIdentityPrincipal: (id, expectedRevision) => requestPlatformModule("identity", "/principals:disable", {
      method: "POST",
      body: { principal_id: id, expected_revision: expectedRevision }
    }),
    changeOwnIdentityPassword: (currentPassword, newPassword) => requestPlatformModule("identity", "/credentials:change-password", {
      method: "POST",
      body: { current_password: currentPassword, new_password: newPassword }
    }),
    createIdentityGrant: a => requestPlatformModule("identity", "/grants", {
      method: "POST",
      body: a
    }),
    revokeIdentityGrant: (a, f, j) => requestPlatformModule("identity", `/grants/${encodeURIComponent(a)}/revoke`, {
      method: "POST",
      query: f,
      body: {
        expected_revision: j
      }
    }),
    identityExplainGrant: a => requestPlatformModule("identity", "/grants:explain", {
      method: "POST",
      body: a
    }),
    identityAgentAccessRequests: (a = {}) => requestPlatformModule("identity", "/access-requests", {
      query: a
    }),
    createIdentityAgentAccessRequest: a => requestPlatformModule("identity", "/access-requests", {
      method: "POST",
      body: a
    }),
    decideIdentityAgentAccessRequest: (id, action, command) => requestPlatformModule("identity", `/access-requests/${encodeURIComponent(id)}/${encodeURIComponent(action)}`, {
      method: "POST",
      body: command
    }),
    identityMachineCredentials: (a = {}) => requestPlatformModule("identity", "/machine-credentials", {
      query: a
    }),
    createIdentityMachineCredential: a => requestPlatformModule("identity", "/machine-credentials", {
      method: "POST",
      body: a
    }),
    createPermissionWorkload: command => requestPlatformModule("identity", "/workload-principals", {
      method: "POST",
      body: command
    }),
    identityWorkloadBindings: scope => requestPlatformModule("identity", "/workload-bindings", { query: scope }),
    changeIdentityWorkloadBinding: command => requestPlatformModule("identity", "/workload-bindings", { method: "POST", body: command }),
    rotateIdentityMachineCredential: (a, f) => requestPlatformModule("identity", `/machine-credentials/${encodeURIComponent(a)}/rotate`, {
      method: "POST",
      body: f
    }),
    disableIdentityMachineCredential: (a, f) => requestPlatformModule("identity", `/machine-credentials/${encodeURIComponent(a)}/disable`, {
      method: "POST",
      body: {
        expected_revision: f,
        network_cidrs: []
      }
    }),
    myAgentCatalog: () => requestPlatformModule("catalog", "/available"),
    catalogDefinitions: (a = {}) => requestPlatformModule("catalog", "/definitions", {
      query: a
    }),
    catalogAvailableDefinitions: (scope, query = {}) => requestPlatformModule("catalog", "/available-definitions", {
      query: { ...scope, limit: 100, ...query }
    }),
    catalogCreateDefinition: a => requestPlatformModule("catalog", "/definitions", {
      method: "POST",
      body: a
    }),
    catalogDefinitionVersions: (a, f = {}) => requestPlatformModule("catalog", `/definitions/${encodeURIComponent(a)}/versions`, {
      query: f
    }),
    catalogVersion: a => requestPlatformModule("catalog", `/versions/${encodeURIComponent(a)}`),
    catalogAvailableDefinitionVersions: (definitionID, scope, query = {}) => requestPlatformModule("catalog", `/available-definitions/${encodeURIComponent(definitionID)}/versions`, {
      query: { ...scope, limit: 100, ...query }
    }),
    catalogCreateVersion: (a, f) => requestPlatformModule("catalog", `/definitions/${encodeURIComponent(a)}/versions`, {
      method: "POST",
      body: f
    }),
    catalogTransitionDefinition: (a, f, j) => requestPlatformModule("catalog", `/definitions/${encodeURIComponent(a)}/${encodeURIComponent(f)}`, {
      method: "POST",
      body: {
        expected_revision: j
      }
    }),
    catalogTransitionVersion: (a, f, j) => requestPlatformModule("catalog", `/versions/${encodeURIComponent(a)}/${encodeURIComponent(f)}`, {
      method: "POST",
      body: {
        expected_revision: j
      }
    }),
    catalogInstallations: (a, f = {}) => requestPlatformModule("catalog", "/installations", {
      query: {
        ...a,
        limit: 100,
        ...f
      }
    }),
    identityInstallationTargets: (scope, purpose, after) => requestPlatformModule("catalog", "/installations", {
      query: { ...scope, view: "permission-targets", purpose, limit: 100, after_id: after }
    }),
    policyAssets: (scope, type) => requestPlatformModule("policyasset", "/assets", { query: { ...scope, ...(type ? { type } : {}), limit: 100 } }),
    policyAssetReferences: scope => requestPlatformModule("policyasset", "/assets", { query: { ...scope, view: "snapshot-references", limit: 100 } }),
    createPolicyAsset: body => requestPlatformModule("policyasset", "/assets", { method: "POST", body }),
    updatePolicyAsset: (type, id, body) => requestPlatformModule("policyasset", `/assets/${encodeURIComponent(type)}/${encodeURIComponent(id)}`, { method: "PUT", body }),
    publishPolicyAsset: (type, id, body) => requestPlatformModule("policyasset", `/assets/${encodeURIComponent(type)}/${encodeURIComponent(id)}/publish`, { method: "POST", body }),
    currentPolicySnapshot: scope => requestPlatformModule("policyasset", "/snapshots/current", { query: scope }),
    publishPolicySnapshot: body => requestPlatformModule("policyasset", "/snapshots/publish", { method: "POST", body }),
    catalogCreateInstallation: a => requestPlatformModule("catalog", "/installations", {
      method: "POST",
      body: a
    }),
    catalogTransitionInstallation: (a, f, j, w) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/transition`, {
      method: "POST",
      body: {
        from: f,
        to: j,
        expected_revision: w
      }
    }),
    catalogRollbackInstallation: (a, f, j) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/rollback`, {
      method: "POST",
      body: {
        version_id: f,
        expected_revision: j
      }
    }),
    catalogUninstallInstallation: (a, f) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/uninstall`, {
      method: "POST",
      body: {
        expected_revision: f
      }
    }),
    catalogDeployments: (a, f, j = {}) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/deployments`, {
      query: {
        ...f,
        limit: 100,
        ...j
      }
    }),
    catalogCreateDeployment: (a, f) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/deployments`, {
      method: "POST",
      body: f
    }),
    catalogObserveDeployment: (a, f, j) => requestPlatformModule("catalog", `/installations/${encodeURIComponent(a)}/deployments/${encodeURIComponent(f)}/observe`, {
      method: "POST",
      body: j
    }),
    userEnrollments: a => requestPlatformModule("identity", "/enrollments", {
      query: a
    }),
    approveEnrollment: (a, f) => requestPlatformModule("identity", `/enrollments/${encodeURIComponent(a)}/approve`, {
      method: "POST",
      body: f
    }),
    rejectEnrollment: (a, f) => requestPlatformModule("identity", `/enrollments/${encodeURIComponent(a)}/reject`, {
      method: "POST",
      body: f
    }),
    conversations: a => requestConversationModule("/sessions", {
      query: a
    }),
    createConversationSession: a => requestConversationModule("/sessions", {
      method: "POST",
      body: a
    }),
    conversation: a => requestConversationModule(`/sessions/${encodeURIComponent(a)}`),
    resumeConversation: a => requestConversationModule(`/sessions/${encodeURIComponent(a)}/resume`, {
      method: "POST",
      body: {}
    }),
    conversationMessages: (a, f) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/messages`, {
      query: f
    }),
    appendConversationMessage: (a, f) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/messages`, {
      method: "POST",
      body: f
    }),
    startConversationRun: (a, f) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/runs`, {
      method: "POST",
      body: f
    }),
    conversationMessageRevisions: (a, f) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/messages/${encodeURIComponent(f)}/revisions`),
    reviseConversationMessage: (a, f, j) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/messages/${encodeURIComponent(f)}/revisions`, {
      method: "POST",
      body: j
    }),
    regenerateConversationAnswer: (a, f, j) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/messages/${encodeURIComponent(f)}/regenerate`, {
      method: "POST",
      body: j
    }),
    createConversationShare: (a, f) => requestConversationModule(`/sessions/${encodeURIComponent(a)}/shares`, {
      method: "POST",
      body: {
        ttl_seconds: Number(f?.expires_in_hours || 24) * 3600,
        include_refs: !!f?.include_references
      }
    }),
    revokeConversationShare: a => requestConversationModule(`/shares/${encodeURIComponent(a)}/revoke`, {
      method: "POST",
      body: {}
    }),
    createConversationExport: a => requestConversationModule("/exports", {
      method: "POST",
      body: a
    }),
    conversationExport: a => requestConversationModule(`/exports/${encodeURIComponent(a)}`),
    requestConversationDeletion: a => requestConversationModule("/deletion-requests", {
      method: "POST",
      body: a
    }),
    conversationDeletionRequests: a => requestConversationModule("/deletion-requests", {
      query: a
    }),
    approveConversationDeletion: a => requestConversationModule(`/deletion-requests/${encodeURIComponent(a)}/approve`, {
      method: "POST",
      body: {}
    }),
    globalConversationSearch: a => requestConversationModule("/managed-search", {
      query: a
    }),
    usageAggregate: a => requestPlatformModule("usage", "/usage/aggregate", {
      query: a
    }),
    usageRuns: a => requestPlatformModule("usage", "/usage/runs", {
      query: a
    }),
    usageRunSteps: (a, f) => requestPlatformModule("usage", `/usage/runs/${encodeURIComponent(a)}/steps`, {
      query: f
    }),
    factoryTemplates: a => requestPlatformModule("agent-factory", "/templates", {
      query: a
    }),
    createFactoryTemplate: a => requestPlatformModule("agent-factory", "/templates", {
      method: "POST",
      body: {
        template_id: a.template_id ?? a.TemplateID,
        name: a.name ?? a.Name,
        language: a.language ?? a.Language,
        framework: a.framework ?? a.Framework
      }
    }),
    factoryTemplate: a => requestPlatformModule("agent-factory", `/templates/${encodeURIComponent(a)}`),
    factoryTemplateVersions: (a, f) => requestPlatformModule("agent-factory", `/templates/${encodeURIComponent(a)}/versions`, {
      query: f
    }),
    createFactoryTemplateVersion: (a, f) => requestPlatformModule("agent-factory", `/templates/${encodeURIComponent(a)}/versions`, {
      method: "POST",
      body: f
    }),
    factoryMappings: a => requestPlatformModule("agent-factory", "/mappings", {
      query: a
    }),
    createFactoryMapping: a => requestPlatformModule("agent-factory", "/mappings", {
      method: "POST",
      body: a
    }),
    factoryMapping: a => requestPlatformModule("agent-factory", `/mappings/${encodeURIComponent(a)}`),
    factoryMappingEvidence: (a, f) => requestPlatformModule("agent-factory", `/mappings/${encodeURIComponent(a)}/evidence`, {
      query: f
    }),
    dryRunFactoryMapping: (a, f) => requestPlatformModule("agent-factory", `/mappings/${encodeURIComponent(a)}/dry-run`, {
      method: "POST",
      body: f
    }),
    publishFactoryMapping: (a, f) => requestPlatformModule("agent-factory", `/mappings/${encodeURIComponent(a)}/publish`, {
      method: "POST",
      body: {
        revision: f
      }
    }),
    // Evaluation product has a single module-owned contract. Actor identity and
    // scope are supplied by the authenticated browser session/Gateway, never by
    // evaluation form payloads.
    evaluationProductAvailability: () => requestPlatformModule("evaluation-product", "/availability"),
    evaluationProductDatasets: a => requestPlatformModule("evaluation-product", "/datasets", { query: a }),
    createEvaluationProductDataset: a => requestPlatformModule("evaluation-product", "/datasets", { method: "POST", body: a }),
    evaluationProductDataset: a => requestPlatformModule("evaluation-product", `/datasets/${encodeURIComponent(a)}`),
    reviewEvaluationProductDataset: (a, f) => requestPlatformModule("evaluation-product", `/datasets/${encodeURIComponent(a)}/review`, { method: "POST", body: f }),
    publishEvaluationProductDataset: (a, f) => requestPlatformModule("evaluation-product", `/datasets/${encodeURIComponent(a)}/publish`, { method: "POST", body: f }),
    evaluationProductSuites: a => requestPlatformModule("evaluation-product", "/suites", { query: a }),
    createEvaluationProductSuite: a => requestPlatformModule("evaluation-product", "/suites", { method: "POST", body: a }),
    evaluationProductSuite: a => requestPlatformModule("evaluation-product", `/suites/${encodeURIComponent(a)}`),
    evaluationProductMetrics: a => requestPlatformModule("evaluation-product", "/metrics", { query: a }),
    createEvaluationProductMetric: a => requestPlatformModule("evaluation-product", "/metrics", { method: "POST", body: a }),
    publishEvaluationProductMetric: (a, f) => requestPlatformModule("evaluation-product", `/metrics/${encodeURIComponent(a)}/publish`, { method: "POST", body: f }),
    evaluationProductRuns: a => requestPlatformModule("evaluation-product", "/runs", { query: a }),
    createEvaluationProductRun: a => requestPlatformModule("evaluation-product", "/runs", { method: "POST", body: a }),
    evaluationProductRun: a => requestPlatformModule("evaluation-product", `/runs/${encodeURIComponent(a)}`),
    cancelEvaluationProductRun: (a, f) => requestPlatformModule("evaluation-product", `/runs/${encodeURIComponent(a)}/cancel`, { method: "POST", body: f }),
    evaluationProductEvidence: a => requestPlatformModule("evaluation-product", "/evidence", { query: a }),
    evaluationProductEvidenceItem: a => requestPlatformModule("evaluation-product", `/evidence/${encodeURIComponent(a)}`),
    evaluationProductReviews: a => requestPlatformModule("evaluation-product", "/reviews", { query: a }),
    createEvaluationProductReview: a => requestPlatformModule("evaluation-product", "/reviews", { method: "POST", body: a }),
    evaluationProductBaselines: a => requestPlatformModule("evaluation-product", "/baselines", { query: a }),
    createEvaluationProductBaseline: a => requestPlatformModule("evaluation-product", "/baselines", { method: "POST", body: a }),
    evaluateEvaluationProductGate: a => requestPlatformModule("evaluation-product", "/gates/evaluate", { method: "POST", body: a }),
    modelProviders: a => requestPlatformModule("model-governance", "/providers", {
      query: a
    }),
    createModelProvider: a => requestPlatformModule("model-governance", "/providers", {
      method: "POST",
      body: a
    }),
    modelProvider: a => requestPlatformModule("model-governance", `/providers/${encodeURIComponent(a)}`),
    testModelProvider: a => requestPlatformModule("model-governance", `/providers/${encodeURIComponent(a)}/test`, {
      method: "POST",
      body: {}
    }),
    approveModelProvider: (a, f) => requestPlatformModule("model-governance", `/providers/${encodeURIComponent(a)}/approve`, {
      method: "POST",
      body: {
        revision: f
      }
    }),
    disableModelProvider: (a, f) => requestPlatformModule("model-governance", `/providers/${encodeURIComponent(a)}/disable`, {
      method: "POST",
      body: {
        revision: f
      }
    }),
    modelDefinitions: a => requestPlatformModule("model-governance", "/models", {
      query: a
    }),
    createModelDefinition: a => requestPlatformModule("model-governance", "/models", {
      method: "POST",
      body: a
    }),
    modelDefinitionVersions: (a, f) => requestPlatformModule("model-governance", `/models/${encodeURIComponent(a)}/versions`, {
      query: f
    }),
    createModelDefinitionVersion: (a, f) => requestPlatformModule("model-governance", `/models/${encodeURIComponent(a)}/versions`, {
      method: "POST",
      body: f
    }),
    approveModelVersion: (a, f, j) => requestPlatformModule("model-governance", `/models/${encodeURIComponent(a)}/versions/${encodeURIComponent(f)}/approve`, {
      method: "POST",
      body: {
        revision: j
      }
    }),
    approveModelDefinitionVersion: (a, f, j) => requestPlatformModule("model-governance", `/models/${encodeURIComponent(a)}/versions/${encodeURIComponent(f)}/approve`, {
      method: "POST",
      body: {
        revision: j
      }
    }),
    modelPrices: a => requestPlatformModule("model-governance", "/prices", {
      query: a
    }),
    modelBillingReconciliations: () => requestPlatformModule("model-billing", "/reconciliations"),
    decideModelBillingReconciliation: a => requestPlatformModule("model-billing", "/reconciliations", {
      method: "POST", body: a
    }),
    createModelPrice: a => requestPlatformModule("model-governance", "/prices", {
      method: "POST",
      body: a
    }),
    approveModelPrice: (a, f) => requestPlatformModule("model-governance", `/prices/${encodeURIComponent(a)}/approve`, {
      method: "POST",
      body: { revision: f }
    }),
    modelDeployments: a => requestPlatformModule("model-governance", "/deployments", {
      query: a
    }),
    createModelDeployment: a => requestPlatformModule("model-governance", "/deployments", {
      method: "POST",
      body: a
    }),
    modelDeployment: a => requestPlatformModule("model-governance", `/deployments/${encodeURIComponent(a)}`),
    modelDeploymentHealth: a => requestPlatformModule("model-governance", `/deployments/${encodeURIComponent(a)}/health`),
    updateModelDeploymentHealth: (a, f, j) => requestPlatformModule("model-governance", `/deployments/${encodeURIComponent(a)}/health`, {
      method: "POST",
      body: {
        revision: f,
        health_status: j
      }
    }),
    modelPolicies: a => requestPlatformModule("model-governance", "/access-policies", {
      query: a
    }),
    createModelPolicy: a => requestPlatformModule("model-governance", "/access-policies", {
      method: "POST",
      body: a
    }),
    approveModelPolicy: (a, f) => requestPlatformModule("model-governance", `/access-policies/${encodeURIComponent(a)}/approve`, {
      method: "POST",
      body: {
        revision: f
      }
    }),
    revokeModelPolicy: (a, f) => requestPlatformModule("model-governance", `/access-policies/${encodeURIComponent(a)}/revoke`, {
      method: "POST",
      body: {
        revision: f
      }
    })
  };
}
export { ApiError, createApiClient, parseSSEChunk, toQuery };

export const api = createApiClient();
