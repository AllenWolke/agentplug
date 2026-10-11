package identity

import "slices"

// Projection describes which management forms can be used in this workspace.
// Mutation handlers additionally validate the exact target, duration and payload.
// A permission administrator's role qualifies them to receive delegation; it
// does not by itself confer the delegated mutation capability.
func managementCapabilityAvailable(snapshot PermissionSnapshot, query PermissionQuery) (bool, error) {
	decision, err := EvaluatePermission(snapshot, query)
	if err != nil {
		return false, err
	}
	switch query.Action {
	case "authorization.change", "access_request.decide", "principal.disable", "membership.manage":
	default:
		return decision.Allowed, nil
	}
	qualified := false
	for _, binding := range snapshot.Bindings {
		if !slices.Contains(decision.BindingIDs, binding.ID) {
			continue
		}
		if binding.RoleCode == "department_admin" && binding.RoleVersion == 2 && departmentAgentPolicyFor(snapshot, query.Scope) != nil && (query.Action == "authorization.change" || query.Action == "access_request.decide") {
			return decision.Allowed, nil
		}
		if binding.RoleCode != "permission_admin" && !(binding.RoleCode == "department_admin" && binding.RoleVersion == 2 && query.Action != "membership.manage") {
			return decision.Allowed, nil
		}
		qualified = true
	}
	// Member management uses the existing permission-admin qualification path,
	// while ordinary organization administrators keep their direct capability.
	if query.Action == "membership.manage" && !qualified {
		qualification := query
		qualification.Action = "authorization.change"
		d, err := EvaluatePermission(snapshot, qualification)
		if err != nil {
			return false, err
		}
		for _, binding := range snapshot.Bindings {
			if binding.RoleCode == "permission_admin" && slices.Contains(d.BindingIDs, binding.ID) {
				qualified = true
			}
		}
	}
	if !qualified {
		return false, nil
	}
	for _, delegation := range snapshot.Delegations {
		if delegation.SubjectID == snapshot.Principal.ID && delegation.Status == "active" && delegation.Effective(query.Now) && delegation.Scope.Contains(query.Scope) && slices.Contains(delegation.ManagementActions, query.Action) {
			return true, nil
		}
	}
	return false, nil
}
