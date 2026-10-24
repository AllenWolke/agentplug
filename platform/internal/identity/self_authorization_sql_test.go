package identity

import (
	"errors"
	"testing"
)

func TestSQLSuperAdministratorCannotDirectlyGrantOwnBusinessRole(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[0]
	command := AuthorizationChangeCommand{
		SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, ExpectedRevision: 1,
		IdempotencyKey: "self-business-role", Reason: "must use an independent administrator",
		Bindings: []RoleBinding{{ID: "self-operator", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1,
			Scope:  ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID},
			Status: "active", Revision: 1, SourceID: "self-authorization-test"}},
	}
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("super administrator's direct self-grant was not rejected: %v", err)
	}
	command.SubjectID = f.actors[2].PrincipalID
	command.Bindings[0].SubjectID = command.SubjectID
	command.Bindings[0].ID = "independent-operator"
	command.IdempotencyKey = "independent-business-role"
	if _, err := f.store.PreviewAuthorizationChange(f.ctx, actor, command); err != nil {
		t.Fatalf("independent administrator cannot preview an ordinary role grant: %v", err)
	}
}
