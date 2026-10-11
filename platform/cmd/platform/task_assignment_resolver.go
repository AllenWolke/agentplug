package main

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type assignmentRunReader interface {
	ReadTaskAssignmentScope(context.Context, string) (sharedkernel.Scope, error)
}
type permissionTaskResolver struct {
	runs assignmentRunReader
}

func (a permissionTaskResolver) ResolvePermissionTask(ctx context.Context, actor sharedkernel.Scope, scope identity.ManagementScope, id string) (identity.DataObject, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" || scope.Validate() != nil || scope.Type != "agent_installation" || id == "" {
		return identity.DataObject{}, identity.ErrInvalidResource
	}
	if a.runs == nil {
		return identity.DataObject{}, identity.ErrInvalidResource
	}
	run, err := a.runs.ReadTaskAssignmentScope(ctx, id)
	if err != nil {
		if errors.Is(err, platformruntime.ErrRunNotFound) {
			return identity.DataObject{}, identity.ErrInvalidResource
		}
		return identity.DataObject{}, err
	}
	if run.RunID != id || run.PrincipalType != "user" || run.PrincipalID == "" || run.AgentInstanceID != scope.ResourceID || run.TenantID != scope.TenantID || run.DepartmentID != scope.DepartmentID || run.ApplicationID != scope.ApplicationID {
		return identity.DataObject{}, identity.ErrInvalidResource
	}
	return identity.DataObject{ID: id, OwnerID: run.PrincipalID, ActorID: run.PrincipalID, Participants: []string{run.PrincipalID}, Scope: scope}, nil
}
