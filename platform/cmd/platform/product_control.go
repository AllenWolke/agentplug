package main

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/agentfactory"
	"github.com/lexagent/platform/internal/evaluationproduct"
	"github.com/lexagent/platform/internal/identity"
)

var errControlActorForbidden = errors.New("control actor is forbidden")

// identityAgentFactoryControl authorizes the Factory against current Identity
// roles; the trusted gateway supplies scope, while Identity remains role owner.
type identityAgentFactoryControl struct{ store identity.Store }

func (a identityAgentFactoryControl) AuthorizeAgentFactory(ctx context.Context, actor agentfactory.Actor, action agentfactory.Action, target agentfactory.Scope) error {
	principal, err := activeIdentityPrincipal(a.store, ctx, actor.PrincipalType, actor.PrincipalID, actor.TenantID)
	if err != nil {
		if errors.Is(err, errControlActorForbidden) {
			return agentfactory.ErrForbidden
		}
		return err
	}
	if target.TenantID != actor.TenantID || target.DepartmentID != actor.DepartmentID || target.ApplicationID != actor.ApplicationID {
		return agentfactory.ErrForbidden
	}
	permissionAction := "agent.develop"
	if action == agentfactory.ActionPublish {
		permissionAction = "release.submit"
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, permissionAction, target.TenantID, target.DepartmentID, target.ApplicationID); handled {
		return controlPermissionError(err, agentfactory.ErrForbidden)
	}
	if hasCatalogRole(principal.Roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin") {
		return nil
	}
	return agentfactory.ErrForbidden
}

// identityEvaluationProductControl keeps review and evaluation management
// within the authenticated application and resolves roles from Identity.
type identityEvaluationProductControl struct{ store identity.Store }

func (a identityEvaluationProductControl) AuthorizeEvaluation(ctx context.Context, actor evaluationproduct.Actor, action evaluationproduct.Action, target evaluationproduct.Scope) error {
	principal, err := activeIdentityPrincipal(a.store, ctx, actor.PrincipalType, actor.PrincipalID, actor.Scope.TenantID)
	if err != nil {
		if errors.Is(err, errControlActorForbidden) {
			return evaluationproduct.ErrForbidden
		}
		return err
	}
	if target != actor.Scope {
		return evaluationproduct.ErrForbidden
	}
	permissionAction := "evaluation.run"
	if action == evaluationproduct.ActionReview || action == evaluationproduct.ActionPublish || action == evaluationproduct.ActionGate {
		permissionAction = "release.approve"
	}
	if handled, err := authorizeVersionedControl(ctx, a.store, actor.PrincipalID, permissionAction, target.TenantID, target.DepartmentID, target.ApplicationID); handled {
		return controlPermissionError(err, evaluationproduct.ErrForbidden)
	}
	roles := principal.Roles
	if hasCatalogRole(roles, "system_admin", "admin", "platform_admin", "department_admin", "application_admin", "evaluation_admin", "evaluation_reviewer") {
		return nil
	}
	return evaluationproduct.ErrForbidden
}

func activeIdentityPrincipal(store identity.Store, ctx context.Context, principalType, principalID, tenantID string) (identity.Principal, error) {
	if store == nil || principalType != string(identity.PrincipalUser) || strings.TrimSpace(principalID) == "" || strings.TrimSpace(tenantID) == "" {
		return identity.Principal{}, errControlActorForbidden
	}
	principal, err := store.GetPrincipal(ctx, identity.PrincipalUser, principalID)
	if err != nil {
		if errors.Is(err, identity.ErrPrincipalNotFound) {
			return identity.Principal{}, errControlActorForbidden
		}
		return identity.Principal{}, err
	}
	if !principal.IsActive || principal.TenantID != tenantID {
		return identity.Principal{}, errControlActorForbidden
	}
	return principal, nil
}
