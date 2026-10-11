// Presentation groups never replace the persisted grant IDs. Independent
// sources and explicit deny records remain individually reviewable.
export function groupResourceGrants(grants) {
  const groups = new Map();
  for (const grant of grants) {
    const key = JSON.stringify([grant.resource_type, grant.resource_id, grant.agent_instance_id]);
    if (!groups.has(key)) groups.set(key, { key, resourceType: grant.resource_type, resourceID: grant.resource_id, installationID: grant.agent_instance_id, grants: [] });
    groups.get(key).grants.push(grant);
  }
  return [...groups.values()];
}

export function toggleGroupAllows(selected, grants) {
  const ids = grants.filter(grant => grant.effect !== "deny").map(grant => grant.id);
  if (!ids.length) return selected;
  return ids.every(id => selected.includes(id)) ? selected.filter(id => !ids.includes(id)) : [...new Set([...selected, ...ids])];
}
