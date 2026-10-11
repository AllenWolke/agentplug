package main

import (
	"context"
	"errors"

	"github.com/lexagent/platform/internal/identity"
)

// The boolean means this principal uses versioned policy. A denial or storage
// error in that mode must never fall through to legacy role-array checks.
func authorizeVersionedControl(ctx context.Context, store identity.Store, id, action, tenant, department, application string) (bool, error) {
	repository, ok := store.(identity.PermissionRepository)
	if !ok {
		return false, nil
	}
	snapshot, err := repository.PermissionSnapshot(ctx, identity.PrincipalUser, id)
	if err != nil {
		return true, err
	}
	if snapshot.Mode == "legacy" || snapshot.Mode == "shadow" {
		return false, nil
	}
	if snapshot.Mode != "v2" {
		return true, identity.ErrInvalidResource
	}
	scope := identity.ManagementScope{Type: "global"}
	if tenant != "" {
		scope = identity.ManagementScope{Type: "tenant", TenantID: tenant}
	}
	if department != "" {
		scope.Type = "department"
		scope.DepartmentID = department
	}
	if application != "" {
		scope.Type = "application"
		scope.ApplicationID = application
	}
	decision, err := repository.ResolvePermission(ctx, identity.PrincipalUser, id, identity.PermissionQuery{Action: action, Scope: scope})
	if err != nil {
		return true, err
	}
	if !decision.Allowed {
		return true, errControlActorForbidden
	}
	return true, nil
}

func controlPermissionError(err, forbidden error) error {
	if errors.Is(err, errControlActorForbidden) || errors.Is(err, identity.ErrPrincipalNotFound) || errors.Is(err, identity.ErrScopeMismatch) {
		return forbidden
	}
	return err
}
