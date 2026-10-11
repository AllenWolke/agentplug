// Kept in memory for one operation; never persist passwords, proofs or tokens.
const PENDING_IDENTIFIER = /^[A-Za-z0-9_.:-]{1,128}$/;
const PENDING_OPERATION_FIELDS = new Set([
  "run_id", "name", "call_id", "payload", "pending_key", "checkpoint_revision"
]);

function validPendingIdentifier(value) {
  return typeof value === "string" && PENDING_IDENTIFIER.test(value);
}

function isPendingReference(operation) {
  return operation !== null && typeof operation === "object" &&
    Object.prototype.hasOwnProperty.call(operation, "pending_key");
}

function validatePendingReference(reference, requestedRunID, requestedKey) {
  if (!reference || typeof reference !== "object" || Array.isArray(reference) ||
      Object.keys(reference).some((key) => !PENDING_OPERATION_FIELDS.has(key)) ||
      !validPendingIdentifier(reference.run_id) || !validPendingIdentifier(reference.name) ||
      !validPendingIdentifier(reference.call_id) || !validPendingIdentifier(reference.pending_key) ||
      reference.run_id !== requestedRunID || reference.pending_key !== requestedKey ||
      !Number.isInteger(reference.checkpoint_revision) || reference.checkpoint_revision < 1 ||
      reference.checkpoint_revision > 64 ||
      (Object.prototype.hasOwnProperty.call(reference, "payload") && reference.payload !== null)) {
    throw new Error("待批准操作引用无效，请重新读取");
  }
  return {
    run_id: reference.run_id,
    name: reference.name,
    call_id: reference.call_id,
    ...(Object.prototype.hasOwnProperty.call(reference, "payload") ? { payload: null } : {}),
    pending_key: reference.pending_key,
    checkpoint_revision: reference.checkpoint_revision
  };
}

function claimsMatchOperationReference(claims, operation, isReference) {
  if (isReference) {
    return claims.pending_key === operation.pending_key &&
      claims.checkpoint_revision === operation.checkpoint_revision;
  }
  return (claims.pending_key === undefined || claims.pending_key === "") &&
    (claims.checkpoint_revision === undefined || claims.checkpoint_revision === 0);
}

function freezeTree(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) freezeTree(child);
  return Object.freeze(value);
}

export function createToolApprovalFlow(client, now = Date.now) {
  let generation = 0;
  let plan = null;
  let busy = false;
  const invalidate = () => { generation++; plan = null; };
  async function preview(operation) {
    if (busy) throw new Error("操作正在办理");
    invalidate();
    const version = generation;
    busy = true;
    try {
      let frozen;
      const referenceMode = isPendingReference(operation);
      if (referenceMode) {
        const runID = operation.run_id;
        const pendingKey = operation.pending_key;
        if (!validPendingIdentifier(runID) || !validPendingIdentifier(pendingKey) ||
            (Object.prototype.hasOwnProperty.call(operation, "payload") && operation.payload !== null)) {
          throw new Error("待批准操作引用无效，请重新读取");
        }
        const resolved = await client.pendingToolOperation(runID, pendingKey);
        if (generation !== version) throw new Error("操作已经变更，请重新预览");
        frozen = validatePendingReference(resolved?.operation, runID, pendingKey);
      } else {
        frozen = JSON.parse(JSON.stringify(operation));
      }
      const value = await client.previewToolApproval(frozen);
      if (generation !== version) throw new Error("操作已经变更，请重新预览");
      if (!value?.claims || value.claims.tool_name !== frozen.name || value.claims.call_id !== frozen.call_id
          || value.claims.version !== "tool-confirmation/v1" || !value.request_digest
          || !claimsMatchOperationReference(value.claims, frozen, referenceMode)
          || !Number.isFinite(value.claims.expires_at) || value.claims.expires_at * 1000 <= now())
        throw new Error("批准预览无效或已到期");
      plan = { operation: frozen, claims: JSON.parse(JSON.stringify(value.claims)), requestDigest: value.request_digest, pending: referenceMode, approved: false, resumeRequested: false };
      return value;
    } finally { busy = false; }
  }
  async function commit(action, password, authenticate) {
    if (busy || !plan || (typeof authenticate !== "function" && !password)) throw new Error("请先预览并完成再次认证");
    if (action !== "approve" && action !== "revoke") throw new Error("无效的批准动作");
    if (action === "approve" && plan.claims.expires_at * 1000 <= now()) {
      invalidate(); throw new Error("批准预览已到期，请重新预览");
    }
    const version = generation;
    const command = {
      operation: JSON.parse(JSON.stringify(plan.operation)),
      claims: JSON.parse(JSON.stringify(plan.claims))
    };
    busy = true;
    try {
      const proof = typeof authenticate === "function"
        ? await authenticate(Object.freeze({ action: `tool.approval.${action}`, request_digest: plan.requestDigest }))
        : await client.toolApprovalStepUp({ ...command, action: `tool.approval.${action}`, current_password: password });
      if (generation !== version) throw new Error("操作已经变更，请重新预览");
      if (!proof?.step_up_token) throw new Error("再次认证未完成");
      if (action === "approve" && plan.claims.expires_at * 1000 <= now()) {
        invalidate(); throw new Error("批准预览已到期，请重新预览");
      }
      const result = await client[action === "approve" ? "approveToolOperation" : "revokeToolOperation"]({ ...command, step_up_token: proof.step_up_token });
      if (generation !== version) throw new Error("操作已经变更，请检查原操作的办理状态");
      if (action === "approve") {
        if (typeof result?.confirmation_token !== "string" || !result.confirmation_token) throw new Error("批准回执无法确认");
        plan = { ...plan, approved: true };
      } else {
        plan = { ...plan, approved: false, resumeRequested: false };
      }
      return result;
    } finally { busy = false; }
  }

  function approvedResumeCommand() {
    if (busy || !plan?.pending || !plan.approved || plan.resumeRequested) throw new Error("请先批准当前待执行操作");
    if (plan.claims.expires_at * 1000 <= now()) throw new Error("批准预览已到期，请重新核对操作");
    const source = plan.operation;
    if (!validPendingIdentifier(source.run_id) || !validPendingIdentifier(source.name) ||
        !validPendingIdentifier(source.call_id) || !validPendingIdentifier(source.pending_key) ||
        !Number.isInteger(source.checkpoint_revision) || source.checkpoint_revision < 1 || source.checkpoint_revision > 64 ||
        plan.claims.tool_name !== source.name || plan.claims.call_id !== source.call_id ||
        plan.claims.pending_key !== source.pending_key || plan.claims.checkpoint_revision !== source.checkpoint_revision) {
      throw new Error("已批准操作引用无法确认，请重新读取");
    }
    const command = {
      operation: {
        run_id: source.run_id,
        name: source.name,
        call_id: source.call_id,
        payload: null,
        pending_key: source.pending_key,
        checkpoint_revision: source.checkpoint_revision
      },
      // Reuse the exact server-issued preview claims; never derive claims from event metadata.
      claims: JSON.parse(JSON.stringify(plan.claims))
    };
    return freezeTree(command);
  }

  async function resumeApproved() {
    if (busy) throw new Error("操作正在办理");
    const version = generation;
    const command = approvedResumeCommand();
    busy = true;
    try {
      const response = await client.resumeApprovedToolOperation(command);
      if (generation !== version) throw new Error("操作已经变更，请核查原运行状态");
      if (response?.resume_requested !== true || response.run_id !== command.operation.run_id ||
          !Number.isSafeInteger(response.revision) || response.revision < 1) {
        throw new Error("恢复请求结果无法确认");
      }
      plan = { ...plan, resumeRequested: true };
      return freezeTree({ resume_requested: true, run_id: response.run_id, revision: response.revision });
    } finally { busy = false; }
  }
  return { preview, commit, approvedResumeCommand, resumeApproved, invalidate };
}
