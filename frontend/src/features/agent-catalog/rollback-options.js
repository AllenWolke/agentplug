// Keep rollback targets limited to immutable published versions of the
// installation's own Agent; the current version is not a rollback target.
// 回滚候选仅允许当前 Agent 的不可变已发布版本，且排除当前版本本身。
export function publishedRollbackOptions(versions, currentVersionID) {
  if (!Array.isArray(versions)) return [];
  return versions.filter((version) =>
    typeof version?.id === "string" &&
    version.id.trim() !== "" &&
    version.id !== currentVersionID &&
    version.status === "published"
  );
}
