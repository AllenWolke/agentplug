package identity

import (
	"slices"
	"time"
)

// Version 1 stays immutable. Version 2 can admit members and grant basic
// application use within the managed company's Agent ceiling (or an explicit
// pre-migration delegation) and its exact department. It cannot appoint administrators,
// grant development/governance roles, export/share data or delegate its authority.
func departmentAdministrationAllows(snapshot PermissionSnapshot, scope ManagementScope, management, role, action string, data DataScope, validity Validity, now time.Time) bool {
	if scope.Validate() != nil || (scope.Type != "application" && scope.Type != "agent_installation") || snapshot.Mode != "v2" || !snapshot.Principal.IsActive || validity.Validate() != nil {
		return false
	}
	if role != "" && !slices.Contains([]string{"operator", "skill_user", "agent_delegate"}, role) {
		return false
	}
	if action != "" && (!slices.Contains([]string{"discover", "run", "cancel", "history.read", "history.continue", "skill.load", "agent.delegate", "knowledge.search", "tool.invoke", "model.generate", "model.embed", "memory.read", "memory.write"}, action) || data.Type != "owner") {
		return false
	}
	decision, err := EvaluatePermission(snapshot, PermissionQuery{Action: management, Scope: scope, Now: now})
	if err != nil || !decision.Allowed {
		return false
	}
	for _, binding := range snapshot.Bindings {
		if binding.RoleCode != "department_admin" || binding.RoleVersion != 2 || !slices.Contains(decision.BindingIDs, binding.ID) || binding.Scope.Type != "department" || !binding.Scope.Contains(scope) {
			continue
		}
		// A subordinate grant must not outlive the authority used to issue it.
		if (management == "authorization.change" || management == "access_request.decide") && binding.ExpiresAt != nil && (validity.ExpiresAt == nil || validity.ExpiresAt.After(*binding.ExpiresAt)) {
			continue
		}
		if binding.StartsAt != nil && validity.StartsAt != nil && validity.StartsAt.Before(*binding.StartsAt) {
			continue
		}
		return true
	}
	return false
}
