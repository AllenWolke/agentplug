package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type assignmentRunStub struct {
	scope sharedkernel.Scope
	err   error
	calls *int
}

func (s assignmentRunStub) ReadTaskAssignmentScope(context.Context, string) (sharedkernel.Scope, error) {
	*s.calls++
	return s.scope, s.err
}

func TestPermissionTaskResolverUsesCanonicalScopedHumanMetadata(t *testing.T) {
	actor := sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "manager"}
	scope := identity.ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "installation"}
	for _, name := range []string{"run", "session-alias", "foreign-instance", "foreign-application", "machine-owner", "empty-owner", "storage-outage", "unknown-run"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			run := actor
			run.RunID, run.AgentInstanceID, run.PrincipalID = "task", "installation", "owner"
			reader := assignmentRunStub{scope: run, calls: &calls}
			switch name {
			case "session-alias":
				reader.scope.RunID = "canonical-task"
			case "foreign-instance":
				reader.scope.AgentInstanceID = "foreign"
			case "foreign-application":
				reader.scope.ApplicationID = "foreign"
			case "machine-owner":
				reader.scope.PrincipalType = "service_principal"
			case "empty-owner":
				reader.scope.PrincipalID = ""
			case "storage-outage":
				reader.err = errors.New("injected metadata outage")
			case "unknown-run":
				reader.err = platformruntime.ErrRunNotFound
			}
			object, err := (permissionTaskResolver{runs: reader}).ResolvePermissionTask(context.Background(), actor, scope, "task")
			if (err == nil) != (name == "run") || calls != 1 {
				t.Fatal(object, err, calls)
			}
			if name == "run" && (object.ID != "task" || object.Scope != scope || object.OwnerID != "owner" || len(object.Participants) != 1 || object.Participants[0] != "owner") {
				t.Fatal("canonical ownership changed", object)
			}
			if name == "unknown-run" && !errors.Is(err, identity.ErrInvalidResource) {
				t.Fatal("unknown run misclassified as service outage", err)
			}
		})
	}
}
