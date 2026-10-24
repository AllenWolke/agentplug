package identity

import (
	"slices"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

const departmentRemovalPurpose = "department_removal"

// Removing a department is an explicit operation. A remaining company
// membership must not preserve that department's old allows or assignments.
// Validate the original request before deriving any revocation IDs.
func validateDepartmentRemoval(owner, target PermissionSnapshot, actor sharedkernel.Scope, c AuthorizationChangeCommand, now time.Time) error {
	if c.DepartmentRemoval == nil && c.Purpose != departmentRemovalPurpose {
		return nil
	}
	if c.Purpose != departmentRemovalPurpose || c.DepartmentRemoval == nil || c.SubjectType != PrincipalUser ||
		c.SubjectID == actor.PrincipalID || c.DepartmentRemoval.Type != "department" || c.DepartmentRemoval.Validate() != nil ||
		c.DepartmentRemoval.TenantID != target.Principal.TenantID || c.Preset != nil || c.AgentSelection != nil ||
		len(c.Bindings)+len(c.Grants)+len(c.Assignments)+len(c.RevokeBindingIDs)+len(c.RevokeGrantIDs)+len(c.RevokeAssignmentIDs) != 0 || len(c.Memberships) == 0 {
		return ErrPermissionDenied
	}
	decision, err := EvaluatePermission(owner, PermissionQuery{Action: "membership.manage", Scope: *c.DepartmentRemoval, Now: now})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return ErrPermissionDenied
	}
	for _, mutation := range c.Memberships {
		if mutation.Status != "revoked" || !c.DepartmentRemoval.Contains(mutation.Scope) {
			return ErrPermissionDenied
		}
	}
	for _, member := range target.Memberships {
		if member.Status == "active" && c.DepartmentRemoval.Contains(member.Scope) && !slices.ContainsFunc(c.Memberships, func(m MembershipMutation) bool {
			return m.ID == member.ID && m.Scope == member.Scope && m.Status == "revoked" && m.ExpectedRevision == member.Revision
		}) {
			return ErrIdentityConflict
		}
	}
	return nil
}

func removedDepartmentContains(command AuthorizationChangeCommand, scope ManagementScope) bool {
	return command.Purpose == departmentRemovalPurpose && command.DepartmentRemoval != nil && command.DepartmentRemoval.Contains(scope)
}
