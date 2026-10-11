package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// PermissionResource is resource ownership, never an authorization decision.
// Providers resolve it from their own catalog; Identity never reads their SQL.
type PermissionResource struct {
	Type, ID, TenantID, DepartmentID, ApplicationID, InstallationID string
	AgentID, AgentVersionID                                         string
	DisplayName                                                     string
}

type PermissionResourceResolver interface {
	ResolvePermissionResource(context.Context, sharedkernel.Scope, string, string) (PermissionResource, error)
}

// Run availability is a Catalog fact, separate from permission to use a resource.
// It is queried only after the explanation caller and installation are validated.
type PermissionRunAvailabilityResolver interface {
	ResolvePermissionRunAvailability(context.Context, sharedkernel.Scope) (string, error)
}

func (s *SQLStore) explanationRunBlockReason(ctx context.Context, subject Principal, query PermissionQuery) (string, error) {
	if query.Action != "run" {
		return "", nil
	}
	resolver, ok := s.capabilityResourceResolver.(PermissionRunAvailabilityResolver)
	if !ok {
		return "", ErrPermissionResourceResolverUnavailable
	}

	reason, err := resolver.ResolvePermissionRunAvailability(ctx, sharedkernel.Scope{
		TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID,
		PrincipalID: subject.ID, PrincipalType: string(subject.Type), AgentInstanceID: query.ResourceID, InstallationID: query.ResourceID,
	})
	if err != nil {
		return "", err
	}
	switch reason {
	case "", "RESOURCE_NOT_PUBLISHED", "RESOURCE_UNAVAILABLE":
		return reason, nil
	default:
		return "", ErrInvalidResource
	}
}

var ErrPermissionResourceResolverUnavailable = errors.New("permission resource resolver unavailable")

func (s *SQLStore) explanationExecutionScope(ctx context.Context, subject Principal, query PermissionQuery) (sharedkernel.Scope, error) {
	scope := sharedkernel.Scope{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID,
		PrincipalID: subject.ID, PrincipalType: string(subject.Type), InstallationID: query.ResourceID, AgentInstanceID: query.ResourceID}
	if s.capabilityResourceResolver == nil {
		return sharedkernel.Scope{}, ErrPermissionResourceResolverUnavailable
	}
	resource, err := s.capabilityResourceResolver.ResolvePermissionResource(ctx, scope, "agent_installation", query.ResourceID)
	if err != nil {
		return sharedkernel.Scope{}, err
	}
	if resource.Type != "agent_installation" || resource.ID != query.ResourceID || resource.InstallationID != scope.InstallationID ||
		resource.TenantID != scope.TenantID || resource.DepartmentID != scope.DepartmentID || resource.ApplicationID != scope.ApplicationID || resource.AgentID == "" || resource.AgentVersionID == "" {
		return sharedkernel.Scope{}, ErrInvalidResource
	}
	scope.AgentID, scope.AgentVersionID = resource.AgentID, resource.AgentVersionID
	return scope, nil
}

// Public explanation requests must resolve ownership through the same narrow
// Catalog/policy ports as Grant creation, after the caller's scope is checked.
func (s *SQLStore) validateExplanationResource(ctx context.Context, subject Principal, query PermissionQuery) error {
	for _, action := range BuiltinPermissionActions() {
		if action.Code != query.Action {
			continue
		}
		if action.Management {
			if query.Scope.Type != "agent_installation" {
				return nil
			}
			if s.permissionResourceResolver == nil {
				return ErrPermissionResourceResolverUnavailable
			}
			_, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID, AgentInstanceID: query.Scope.ResourceID, InstallationID: query.Scope.ResourceID}, query.Scope.ResourceID)
			return err
		}
		if action.ResourceType != query.ResourceType || !validPermissionResourceID(query.ResourceID) {
			return ErrInvalidResource
		}
		installation := query.ResourceID
		if query.ResourceType != "agent_installation" {
			if query.Scope.Type != "agent_installation" {
				return ErrInvalidResource
			}
			installation = query.Scope.ResourceID
		} else if query.Scope.Type == "agent_installation" && query.Scope.ResourceID != installation {
			return ErrInvalidResource
		}
		if s.permissionResourceResolver == nil || query.ResourceType != "agent_installation" && s.capabilityResourceResolver == nil {
			return ErrPermissionResourceResolverUnavailable
		}
		return s.validateGrantResource(ctx, Grant{SubjectID: subject.ID, SubjectType: subject.Type, TenantID: query.Scope.TenantID, DepartmentID: query.Scope.DepartmentID, ApplicationID: query.Scope.ApplicationID, AgentInstanceID: installation, ResourceType: query.ResourceType, ResourceID: query.ResourceID})
	}
	return nil // Unknown actions retain the evaluator's stable deny reason.
}

func (s *SQLStore) SetCapabilityResourceResolver(resolver PermissionResourceResolver) {
	s.capabilityResourceResolver = resolver
}

func validPermissionResourceID(id string) bool {
	return id != "" && len(id) <= 128 && strings.TrimSpace(id) == id && !strings.ContainsAny(id, "*\x00\r\n")
}

func (s *SQLStore) validateGrantResource(ctx context.Context, grant Grant) error {
	if !validPermissionResourceID(grant.ResourceID) || !validPermissionResourceID(grant.AgentInstanceID) || s.permissionResourceResolver == nil {
		return ErrInvalidResource
	}
	scope := sharedkernel.Scope{TenantID: grant.TenantID, DepartmentID: grant.DepartmentID, ApplicationID: grant.ApplicationID, PrincipalID: grant.SubjectID, PrincipalType: string(grant.SubjectType), AgentInstanceID: grant.AgentInstanceID, InstallationID: grant.AgentInstanceID}
	if _, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, scope, grant.AgentInstanceID); err != nil {
		return err
	}
	if grant.ResourceType == "agent_installation" {
		if grant.ResourceID != grant.AgentInstanceID {
			return ErrInvalidResource
		}
		return nil
	}
	if s.capabilityResourceResolver == nil {
		return ErrInvalidResource
	}
	resource, err := s.capabilityResourceResolver.ResolvePermissionResource(ctx, scope, grant.ResourceType, grant.ResourceID)
	if err != nil {
		return err
	}
	if resource.Type != grant.ResourceType || resource.ID != grant.ResourceID || resource.TenantID != scope.TenantID || resource.DepartmentID != scope.DepartmentID || resource.ApplicationID != scope.ApplicationID || resource.InstallationID != scope.InstallationID {
		return ErrInvalidResource
	}
	return nil
}

func permissionRequestResourceGrant(item PermissionRequestItem, subject string) (Grant, error) {
	typ := ""
	for _, action := range BuiltinPermissionActions() {
		if action.Code == item.Action && !action.Management {
			typ = action.ResourceType
		}
	}
	if typ == "" || item.ResourceType != "" && item.ResourceType != typ {
		return Grant{}, ErrInvalidResource
	}
	installation := item.InstallationID
	if typ == "agent_installation" {
		if installation != "" && installation != item.ResourceID {
			return Grant{}, ErrInvalidResource
		}
		installation = item.ResourceID
	}
	if !validPermissionResourceID(installation) || !validPermissionResourceID(item.ResourceID) {
		return Grant{}, ErrInvalidResource
	}
	return Grant{SubjectType: PrincipalUser, SubjectID: subject, TenantID: item.Scope.TenantID, DepartmentID: item.Scope.DepartmentID, ApplicationID: item.Scope.ApplicationID, AgentInstanceID: installation, ResourceType: typ, ResourceID: item.ResourceID, Action: item.Action, Effect: "allow", Status: "active", Revision: 1, Validity: item.Validity, DataScope: item.DataScope}, nil
}

// A capability delegation is tied to its installation as well as its typed ID.
func grantAuthorizationScope(grant Grant) ManagementScope {
	scope := ManagementScope{Type: "application", TenantID: grant.TenantID, DepartmentID: grant.DepartmentID, ApplicationID: grant.ApplicationID}
	if grant.ResourceType != "agent_installation" {
		scope.Type = "agent_installation"
		scope.ResourceID = grant.AgentInstanceID
	}
	return scope
}
