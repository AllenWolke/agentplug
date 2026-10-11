package main

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/conversation"
	"github.com/lexagent/platform/internal/identity"
)

type identityConversationAccess struct{ store identity.Store }

func (a identityConversationAccess) snapshot(ctx context.Context, scope conversation.Scope) (identity.PermissionSnapshot, error) {
	if a.store == nil || scope.Validate() != nil || scope.PrincipalType != "user" {
		return identity.PermissionSnapshot{}, conversation.ErrForbidden
	}
	repository, ok := a.store.(identity.PermissionRepository)
	if !ok {
		return identity.PermissionSnapshot{}, errors.New("permission repository unavailable")
	}
	snapshot, err := repository.PermissionSnapshot(ctx, identity.PrincipalUser, scope.PrincipalID)
	if err != nil {
		return snapshot, err
	}
	if snapshot.Principal.Validate() != nil || !snapshot.Principal.IsActive || snapshot.Principal.ID != scope.PrincipalID || snapshot.Principal.TenantID != scope.TenantID || snapshot.Principal.Type != identity.PrincipalUser || snapshot.Mode != "v2" && snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
		return snapshot, conversation.ErrForbidden
	}
	return snapshot, nil
}

func (a identityConversationAccess) ReadPlan(ctx context.Context, scope conversation.Scope) (conversation.HistoryAccessPlan, error) {
	return a.actionReadPlan(ctx, scope, "history.read")
}

func (a identityConversationAccess) DeletionReadPlan(ctx context.Context, scope conversation.Scope) (conversation.HistoryAccessPlan, error) {
	return a.actionReadPlan(ctx, scope, "business.review")
}

func (a identityConversationAccess) actionReadPlan(ctx context.Context, scope conversation.Scope, action string) (conversation.HistoryAccessPlan, error) {
	snapshot, err := a.snapshot(ctx, scope)
	if err != nil {
		return conversation.HistoryAccessPlan{}, err
	}
	if snapshot.Mode != "v2" {
		return conversation.HistoryAccessPlan{Legacy: true}, nil
	}
	app := identity.ManagementScope{Type: "application", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
	plan, err := identity.CompileResourceDataPlan(snapshot, action, app, time.Now().UTC())
	if err != nil {
		return conversation.HistoryAccessPlan{}, err
	}
	convert := func(clauses []identity.ResourceDataClause) []conversation.HistoryDataClause {
		result := []conversation.HistoryDataClause{}
		for _, clause := range clauses {
			result = append(result, conversation.HistoryDataClause{InstallationID: clause.ResourceID, Type: clause.DataScope.Type, IDs: append([]string(nil), clause.DataScope.IDs...)})
		}
		return result
	}
	return conversation.HistoryAccessPlan{Allow: convert(plan.Allow), Deny: convert(plan.Deny)}, nil
}

func (a identityConversationAccess) Authorize(ctx context.Context, scope conversation.Scope, resource conversation.SessionResource, action string) error {
	snapshot, err := a.snapshot(ctx, scope)
	if err != nil {
		return err
	}
	if resource.ID == "" || resource.OwnerID == "" || resource.PrincipalType != "user" {
		return conversation.ErrForbidden
	}
	if snapshot.Mode != "v2" {
		if resource.OwnerID == scope.PrincipalID {
			return nil
		}
		return conversation.ErrForbidden
	}
	if resource.InstallationID == "" || resource.AgentID == "" || resource.AgentVersionID == "" {
		return conversation.ErrForbidden
	}
	installation := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: resource.InstallationID}
	object := identity.DataObject{ID: resource.ID, OwnerID: resource.OwnerID, ActorID: resource.OwnerID, Participants: []string{resource.OwnerID}, Scope: installation}
	// Execution/task assignment IDs do not establish session-wide authority.
	// Session assignments need their own canonical provenance before use.
	snapshot.Assignments = nil
	decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{Action: action, Scope: installation, ResourceType: "agent_installation", ResourceID: resource.InstallationID, Object: &object, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return conversation.ErrForbidden
	}
	return nil
}

func (a identityConversationAccess) Project(ctx context.Context, scope conversation.Scope, items []conversation.Summary) ([]conversation.Summary, error) {
	snapshot, err := a.snapshot(ctx, scope)
	if err != nil {
		return nil, err
	}
	if snapshot.Mode != "v2" {
		return items, nil
	}
	snapshot.Assignments = nil
	now := time.Now().UTC()
	result := append([]conversation.Summary(nil), items...)
	for i := range result {
		item := &result[i]
		installation := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: item.InstallationID}
		object := identity.DataObject{ID: item.ID, OwnerID: item.OwnerID, ActorID: item.OwnerID, Participants: []string{item.OwnerID}, Scope: installation}
		item.Permissions = map[string]bool{}
		for _, action := range []string{"history.read", "run", "history.continue", "history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request"} {
			decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{Action: action, Scope: installation, ResourceType: "agent_installation", ResourceID: item.InstallationID, Object: &object, Now: now})
			if err != nil {
				return nil, err
			}
			if action == "history.read" && !decision.Allowed {
				return nil, conversation.ErrForbidden
			}
			item.Permissions[action] = decision.Allowed && (action == "history.read" || item.OwnerID == scope.PrincipalID)
		}
		item.CanContinue = item.CanContinue && item.Permissions["history.continue"] && item.Permissions["run"]
	}
	return result, nil
}
