package identity

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrPermissionExplanationObjectNotFound = errors.New("permission explanation object not found")

type PermissionObjectExplanationRepository interface {
	ExplainPermissionObject(context.Context, sharedkernel.Scope, PrincipalType, string, PermissionQuery, string) (PermissionExplanation, error)
}

func (s *SQLStore) ExplainPermissionObject(ctx context.Context, actor sharedkernel.Scope, kind PrincipalType, subject string, query PermissionQuery, objectID string) (PermissionExplanation, error) {
	if !validPermissionResourceID(objectID) || query.Scope.Type != "agent_installation" || query.ResourceType != "agent_installation" || query.Scope.ResourceID != query.ResourceID {
		return PermissionExplanation{}, ErrInvalidResource
	}
	switch query.Action {
	case "history.read", "history.continue", "history.revise", "history.regenerate", "history.share", "history.export", "history.delete.request", "cancel", "business.review", "business.content.read":
	default:
		return PermissionExplanation{}, ErrInvalidResource
	}
	return s.explainPermission(ctx, actor, kind, subject, query, objectID)
}

func (s *SQLStore) resolveExplanationObject(ctx context.Context, actor sharedkernel.Scope, viewer PermissionSnapshot, query PermissionQuery, id string) (DataObject, error) {
	if s.permissionTaskResolver == nil {
		return DataObject{}, ErrPermissionResourceResolverUnavailable
	}
	object, err := s.permissionTaskResolver.ResolvePermissionTask(ctx, actor, query.Scope, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrInvalidResource) || errors.Is(err, ErrPermissionDenied) {
			return DataObject{}, ErrPermissionExplanationObjectNotFound
		}
		return DataObject{}, err
	}
	if object.ID != id || object.Scope != query.Scope || object.OwnerID == "" {
		return DataObject{}, ErrPermissionExplanationObjectNotFound
	}
	object = canonicalAssignmentObject(object)
	visible, err := explanationObjectVisible(viewer, query, object)
	if err != nil {
		return DataObject{}, err
	}
	if !visible {
		return DataObject{}, ErrPermissionExplanationObjectNotFound
	}
	return object, nil
}

// The diagnostic returns no body or participant IDs. A caller must nevertheless
// be able to inspect this object's permission metadata, not just its application.
func explanationObjectVisible(viewer PermissionSnapshot, query PermissionQuery, object DataObject) (bool, error) {
	management, err := EvaluatePermission(viewer, PermissionQuery{Action: "authorization.read", Scope: query.Scope, Now: query.Now})
	if err != nil || management.Allowed {
		return management.Allowed, err
	}
	query.Object = &object
	for _, action := range []string{query.Action, "history.read", "business.content.read"} {
		query.Action = action
		d, err := EvaluatePermission(viewer, query)
		if err != nil {
			return false, err
		}
		// This reason is reached only after a matching data Grant; it explains a
		// separation-of-duties refusal without hiding one's own assigned task.
		if d.Allowed || d.Reason == "SELF_REVIEW_DENIED" {
			return true, nil
		}
	}
	return false, nil
}

func explanationGrantMatchesObject(snapshot PermissionSnapshot, query PermissionQuery, grant Grant) bool {
	if query.Object == nil {
		return true
	}
	object := *query.Object
	object.AssignedTo = nil
	if grant.DataScope.Type == "assigned_task" && assignedObjectMatches(snapshot, query) {
		object.AssignedTo = []string{snapshot.Principal.ID}
	}
	scope := ManagementScope{Type: "application", TenantID: grant.TenantID, DepartmentID: grant.DepartmentID, ApplicationID: grant.ApplicationID}
	return grant.DataScope.Allows(snapshot.Principal.ID, scope, object)
}

var _ PermissionObjectExplanationRepository = (*SQLStore)(nil)
