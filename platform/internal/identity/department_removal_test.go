package identity

import (
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestDepartmentRemovalRequiresCompleteBoundedMembershipRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*AuthorizationChangeCommand)
	}{
		{"marker without purpose", func(c *AuthorizationChangeCommand) { c.Purpose = "" }},
		{"purpose without scope", func(c *AuthorizationChangeCommand) { c.DepartmentRemoval = nil }},
		{"wider scope", func(c *AuthorizationChangeCommand) {
			c.DepartmentRemoval.Type, c.DepartmentRemoval.DepartmentID = "tenant", ""
		}},
		{"different department", func(c *AuthorizationChangeCommand) { c.DepartmentRemoval.DepartmentID = "other" }},
		{"incomplete removal", func(c *AuthorizationChangeCommand) { c.Memberships = c.Memberships[:1] }},
		{"activate instead of remove", func(c *AuthorizationChangeCommand) { c.Memberships[0].Status = "active" }},
		{"preset smuggling", func(c *AuthorizationChangeCommand) { c.Preset = &PresetSelection{Code: "operator", Version: 1} }},
		{"explicit revoke smuggling", func(c *AuthorizationChangeCommand) { c.RevokeGrantIDs = []string{"deny"} }},
		{"self removal", func(c *AuthorizationChangeCommand) { c.SubjectID = "department.manager" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner, target, actor, _ := departmentAccessFixture()
			_, query := permissionFixture()
			department := ManagementScope{Type: "department", TenantID: "t", DepartmentID: "d"}
			target.Memberships = append(target.Memberships, Membership{ID: "dept-member", SubjectID: target.Principal.ID, Scope: department, Status: "active", Revision: 1})
			c := AuthorizationChangeCommand{Purpose: departmentRemovalPurpose, DepartmentRemoval: &department, SubjectType: PrincipalUser, SubjectID: target.Principal.ID,
				Memberships: []MembershipMutation{{ID: "m", Scope: target.Memberships[0].Scope, ExpectedRevision: 1, Status: "revoked"}, {ID: "dept-member", Scope: department, ExpectedRevision: 1, Status: "revoked"}}}
			if err := validateDepartmentRemoval(owner, target, actor, c, query.Now); err != nil {
				t.Fatal("valid department removal rejected", err)
			}
			tc.change(&c)
			if err := validateDepartmentRemoval(owner, target, actor, c, query.Now); err == nil {
				t.Fatal("unbounded department removal accepted")
			}
		})
	}
}

func TestDepartmentManagersCannotAlterPeerMemberships(t *testing.T) {
	owner, target, actor, _ := departmentAccessFixture()
	_, query := permissionFixture()
	department := ManagementScope{Type: "department", TenantID: "t", DepartmentID: "d"}
	target.Bindings = append(target.Bindings, RoleBinding{ID: "peer-admin", SubjectID: target.Principal.ID, RoleCode: "department_admin", RoleVersion: 2, Scope: department, Status: "active", Revision: 1})
	if _, err := authorizeMembershipMutation(owner, target, actor, department, Validity{}, query.Now); err == nil {
		t.Fatal("department administrator changed a peer's membership")
	}
	owner.Bindings = []RoleBinding{{ID: "root", SubjectID: owner.Principal.ID, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1}}
	if _, err := authorizeMembershipMutation(owner, target, sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: owner.Principal.ID}, department, Validity{}, query.Now); err != nil {
		t.Fatal("system administrator cannot manage department administrator", err)
	}
}
