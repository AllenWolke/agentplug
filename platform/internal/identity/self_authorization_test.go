package identity

import (
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSelfAuthorizationRejectsAllWaysOfIncreasingBusinessAccess(t *testing.T) {
	actor := sharedkernel.Scope{PrincipalType: "user", PrincipalID: "system.admin"}
	target := PermissionSnapshot{Grants: []Grant{{ID: "deny", Effect: "deny"}, {ID: "allow", Effect: "allow"}}}
	cases := []struct {
		name   string
		change AuthorizationChangeCommand
		denied bool
	}{
		{"role", AuthorizationChangeCommand{Bindings: []RoleBinding{{RoleCode: "operator"}}}, true},
		{"resource", AuthorizationChangeCommand{Grants: []Grant{{Effect: "allow"}}}, true},
		{"preset", AuthorizationChangeCommand{Preset: &PresetSelection{Code: "operator", Version: 1}}, true},
		{"assignment", AuthorizationChangeCommand{Assignments: []TaskAssignment{{}}}, true},
		{"membership", AuthorizationChangeCommand{Memberships: []MembershipMutation{{Status: "active"}}}, true},
		{"remove-deny", AuthorizationChangeCommand{RevokeGrantIDs: []string{"deny"}}, true},
		{"remove-allow", AuthorizationChangeCommand{RevokeGrantIDs: []string{"allow"}}, false},
		{"leave-membership", AuthorizationChangeCommand{Memberships: []MembershipMutation{{Status: "revoked"}}}, false},
		{"leave-role", AuthorizationChangeCommand{RevokeBindingIDs: []string{"operator"}}, false},
		{"unassign", AuthorizationChangeCommand{RevokeAssignmentIDs: []string{"assignment"}}, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			item.change.SubjectType, item.change.SubjectID = PrincipalUser, "System.Admin"
			err := authorizeSelfAuthorizationChange(actor, item.change, target)
			if errors.Is(err, ErrPermissionDenied) != item.denied {
				t.Fatalf("self authorization decision = %v; want denied %v", err, item.denied)
			}
			item.change.SubjectID = "other.user"
			if err := authorizeSelfAuthorizationChange(actor, item.change, target); err != nil {
				t.Fatalf("independent authorization unexpectedly blocked: %v", err)
			}
		})
	}
}
