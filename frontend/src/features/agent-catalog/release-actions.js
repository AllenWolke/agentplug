import { hasManagementAction, isPlatformAdmin } from "../../config.js";

export function canSubmitCatalogRelease(user) {
  const legacy = user?.policy_mode === undefined || ["legacy", "shadow"].includes(user.policy_mode);
  return legacy ? isPlatformAdmin(user) : hasManagementAction(user, "release.submit");
}

export function canApproveCatalogRelease(user, item) {
  const legacy = user?.policy_mode === undefined || ["legacy", "shadow"].includes(user.policy_mode);
  const allowed = legacy ? isPlatformAdmin(user) : hasManagementAction(user, "release.approve");
  return Boolean(allowed && item?.status === "evaluated" && item.submitted_by && item.submitted_by !== user?.username);
}
