import { hasManagementAction, isAppAdmin } from "../../config.js";

export const POLICY_ASSET_TYPES = ["model", "prompt", "tool", "memory", "knowledge", "runtime"];

export function policyAssetActions(user) {
  if (user?.policy_mode === undefined || ["legacy", "shadow"].includes(user.policy_mode)) {
    return { types: isAppAdmin(user) ? POLICY_ASSET_TYPES : [], snapshot: isAppAdmin(user) };
  }
  const snapshot = hasManagementAction(user, "policy.manage");
  const types = POLICY_ASSET_TYPES.filter(type => hasManagementAction(user, type === "prompt" ? "prompt.manage" : type === "tool" ? "tool.manage" : "policy.manage"));
  return { types, snapshot };
}
