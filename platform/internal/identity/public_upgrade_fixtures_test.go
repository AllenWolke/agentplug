package identity

import (
	"context"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func departmentAccessFixture() (PermissionSnapshot, PermissionSnapshot, sharedkernel.Scope, AuthorizationChangeCommand) {
	target, q := permissionFixture()
	owner := target
	owner.Principal.ID = "department.manager"
	department := ManagementScope{Type: "department", TenantID: "t", DepartmentID: "d"}
	owner.Memberships = []Membership{{ID: "manager-member", SubjectID: owner.Principal.ID, Scope: department, Status: "active", Revision: 1}}
	owner.Bindings = []RoleBinding{{ID: "manager-role", SubjectID: owner.Principal.ID, Scope: department, RoleCode: "department_admin", RoleVersion: 3, Status: "active", Revision: 1}}
	owner.Grants = nil
	actor := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: owner.Principal.ID, PrincipalType: "user"}
	c := AuthorizationChangeCommand{Purpose: departmentAgentAccessPurpose, SubjectType: PrincipalUser, SubjectID: target.Principal.ID,
		Preset: &PresetSelection{Code: "operator", Version: 1, Scope: q.Scope, ResourceIDs: []string{"i"}}}
	return owner, target, actor, c
}

type departmentAvailabilityFixture struct{ permissionTestResourceResolver }

func (departmentAvailabilityFixture) ResolvePermissionResource(context.Context, sharedkernel.Scope, string, string) (PermissionResource, error) {
	return PermissionResource{}, ErrInvalidResource
}
func (departmentAvailabilityFixture) ResolvePermissionRunAvailability(context.Context, sharedkernel.Scope) (string, error) {
	return "", nil
}
