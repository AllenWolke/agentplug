// An object's current server projection is the authority for v2 controls.
// Global roles/capabilities cannot substitute for that object's data scope.
export function canStartAgentRun(user, agent) {
  if (agent?.access_status !== "granted") return false;
  if (user?.policy_mode === "v2") return agent.permissions?.discover === true && agent.permissions?.run === true;
  return user?.policy_mode === undefined || ["legacy", "shadow"].includes(user.policy_mode);
}

export function conversationActions(user, session) {
  const actions = { read: false, continue: false, revise: false, regenerate: false, share: false, export: false, delete: false };
  if (!session?.id) return actions;
  if (user?.policy_mode === "v2") {
    const permissions = session.permissions || {};
    actions.read = permissions["history.read"] === true;
    actions.continue = session.can_continue === true && permissions.run === true && permissions["history.continue"] === true;
    for (const [key, action] of Object.entries({ revise: "history.revise", regenerate: "history.regenerate", share: "history.share", export: "history.export", delete: "history.delete.request" })) actions[key] = permissions[action] === true;
    return actions;
  }
  if (user?.policy_mode !== undefined && !["legacy", "shadow"].includes(user.policy_mode)) return actions;
  if (session.owner_id && session.owner_id !== user?.username) return actions;
  return { read: true, continue: session.can_continue !== false, revise: true, regenerate: true, share: true, export: true, delete: true };
}

// Preserve failed selections so a partial batch is visible and retryable.
export async function applyConversationBatch(ids, operation) {
  const results = await Promise.allSettled(ids.map(id => Promise.resolve().then(() => operation(id))));
  return {
    succeeded: ids.filter((_, index) => results[index].status === "fulfilled"),
    failed: results.flatMap((result, index) => result.status === "rejected" ? [{ id: ids[index], message: result.reason?.message || "操作失败" }] : []),
    values: results.flatMap(result => result.status === "fulfilled" ? [result.value] : []),
  };
}
