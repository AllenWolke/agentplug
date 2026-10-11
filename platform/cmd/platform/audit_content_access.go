package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type identityAuditContentControl struct {
	store identity.Store
	runs  assignmentRunReader
}

func (a *identityAuditContentControl) Authorize(ctx context.Context, actor sharedkernel.Scope, event audit.Event, action string) error {
	if a.store == nil || actor.Validate() != nil || actor.PrincipalType != "user" || event.Summary != "" || (action != "audit.content.read" && action != "audit.export") || event.TenantID != actor.TenantID || event.DepartmentID != actor.DepartmentID || event.ApplicationID != actor.ApplicationID {
		return audit.ErrContentForbidden
	}
	repository, ok := a.store.(identity.PermissionRepository)
	if !ok {
		return audit.ErrContentForbidden
	}
	snapshot, err := repository.PermissionSnapshot(ctx, identity.PrincipalUser, actor.PrincipalID)
	if err != nil {
		return err
	}
	// New sensitive endpoints require explicit v2 authorization. Legacy metadata
	// access remains compatible; an old auditor/admin array never opens content.
	if snapshot.Mode != "v2" || !snapshot.Principal.IsActive || snapshot.Principal.ID != actor.PrincipalID || snapshot.Principal.TenantID != actor.TenantID {
		return audit.ErrContentForbidden
	}
	var owner sharedkernel.Scope
	switch event.AggregateType {
	case "agent_run", "run":
		if a.runs == nil {
			return audit.ErrContentForbidden
		}
		owner, err = a.runs.ReadTaskAssignmentScope(ctx, event.AggregateID)
		if errors.Is(err, platformruntime.ErrRunNotFound) {
			return audit.ErrContentForbidden
		}
	default:
		// Events without a verified business installation cannot inherit a grant
		// from an unrelated installation, including identity administration events.
		return audit.ErrContentForbidden
	}
	if err != nil {
		return err
	}
	if owner.Validate() != nil || owner.RunID != event.AggregateID || owner.AgentInstanceID == "" || owner.TenantID != event.TenantID || owner.DepartmentID != event.DepartmentID || owner.ApplicationID != event.ApplicationID {
		return audit.ErrContentForbidden
	}
	scope := identity.ManagementScope{Type: "agent_installation", TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, ResourceID: owner.AgentInstanceID}
	object := identity.DataObject{ID: owner.RunID, OwnerID: owner.PrincipalID, ActorID: owner.PrincipalID, Participants: []string{owner.PrincipalID}, Scope: scope}
	decision, err := repository.ResolvePermission(ctx, identity.PrincipalUser, actor.PrincipalID, identity.PermissionQuery{Action: action, Scope: scope, ResourceType: "agent_installation", ResourceID: owner.AgentInstanceID, Object: &object})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return audit.ErrContentForbidden
	}
	return nil
}
