package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

var errBusinessReviewForbidden = execution.ErrReviewPermissionDenied

type identityBusinessReviewControl struct{ store identity.Store }

// ownerScope is the durable execution scope loaded by Execution, never a
// browser's claimed owner or installation. Management roles alone grant no
// business content or review permission under v2.
func (a identityBusinessReviewControl) Authorize(ctx context.Context, ownerScope sharedkernel.Scope, reviewerID, action string) error {
	if reviewerID == ownerScope.PrincipalID || action != "business.content.read" && action != "business.review" {
		return errBusinessReviewForbidden
	}
	return authorizeBusinessResource(ctx, a.store, ownerScope, reviewerID, action)
}

func authorizeBusinessResource(ctx context.Context, store identity.Store, ownerScope sharedkernel.Scope, reviewerID, action string) error {
	if store == nil || ownerScope.Validate() != nil || ownerScope.AgentInstanceID == "" || ownerScope.RunID == "" || reviewerID == "" {
		return errBusinessReviewForbidden
	}
	principal, err := store.GetPrincipal(ctx, identity.PrincipalUser, reviewerID)
	if err != nil {
		if errors.Is(err, identity.ErrPrincipalNotFound) {
			return errBusinessReviewForbidden
		}
		return err
	}
	if !principal.IsActive || principal.Type != identity.PrincipalUser || principal.ID != reviewerID || principal.TenantID != ownerScope.TenantID {
		return errBusinessReviewForbidden
	}
	if repository, ok := store.(identity.PermissionRepository); ok {
		snapshot, err := repository.PermissionSnapshot(ctx, identity.PrincipalUser, reviewerID)
		if err != nil {
			return err
		}
		if snapshot.Mode == "v2" {
			scope := identity.ManagementScope{Type: "agent_installation", TenantID: ownerScope.TenantID, DepartmentID: ownerScope.DepartmentID, ApplicationID: ownerScope.ApplicationID, ResourceID: ownerScope.AgentInstanceID}
			object := identity.DataObject{ID: ownerScope.RunID, OwnerID: ownerScope.PrincipalID, Scope: scope, Participants: []string{ownerScope.PrincipalID}}
			decision, err := repository.ResolvePermission(ctx, identity.PrincipalUser, reviewerID, identity.PermissionQuery{Action: action, Scope: scope, ResourceType: "agent_installation", ResourceID: ownerScope.AgentInstanceID, Object: &object})
			if err != nil {
				return err
			}
			if !decision.Allowed {
				return errBusinessReviewForbidden
			}
			return nil
		}
		if snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
			return errBusinessReviewForbidden
		}
	}
	if action == "history.read" || action == "cancel" {
		if ownerScope.PrincipalType == "user" && reviewerID == ownerScope.PrincipalID {
			return nil
		}
		return errBusinessReviewForbidden
	}
	for _, role := range principal.Roles {
		if role == "reviewer" || role == "admin" {
			return nil
		}
	}
	return errBusinessReviewForbidden
}
