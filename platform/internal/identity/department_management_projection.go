package identity

import (
	"slices"
	"strings"
	"time"
)

// Department administration is independent of the current application context.
// Project exact department scopes instead of adding their actions to the current
// application's capabilities. Handlers continue to check live target authority.
func departmentManagementScopes(snapshot PermissionSnapshot, now time.Time) ([]ManagementScope, error) {
	scopes := []ManagementScope{}
	if snapshot.Mode != "v2" || snapshot.Principal.Type != PrincipalUser || !snapshot.Principal.IsActive {
		return scopes, nil
	}
	seen := map[ManagementScope]bool{}
	for _, binding := range snapshot.Bindings {
		scope := binding.Scope
		if binding.SubjectID != snapshot.Principal.ID || binding.Status != "active" || !binding.Effective(now) ||
			scope.Type != "department" || scope.TenantID != snapshot.Principal.TenantID || scope.Validate() != nil || seen[scope] {
			continue
		}
		membership, err := managementCapabilityAvailable(snapshot, PermissionQuery{Action: "membership.manage", Scope: scope, Now: now})
		if err != nil {
			return nil, err
		}
		agents, err := canManageDepartmentAgentAccess(snapshot, scope, now)
		if err != nil {
			return nil, err
		}
		if membership && (agents || slices.ContainsFunc(snapshot.Bindings, func(b RoleBinding) bool {
			return b.RoleCode == "department_admin" && b.RoleVersion == 2 && b.Scope == scope && b.Status == "active" && b.Effective(now)
		})) {
			scopes = append(scopes, scope)
			seen[scope] = true
		}
	}
	slices.SortFunc(scopes, func(a, b ManagementScope) int { return strings.Compare(a.DepartmentID, b.DepartmentID) })
	return scopes, nil
}
