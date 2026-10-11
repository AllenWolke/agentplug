package identity

import (
	"context"
	"strings"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// The OAuth action remains a protocol restriction; it is not an IAM action.
func machinePermissionAction(action string) string {
	switch action {
	case "run", "cancel":
		return action
	case "read", "events":
		return "history.read"
	case "resume":
		return "history.continue"
	default:
		return ""
	}
}

func checkMachinePermission(ctx context.Context, store Store, scope sharedkernel.Scope, action string, object *DataObject) (AccessDecision, error) {
	if policy, ok := store.(PermissionRepository); ok {
		snapshot, err := policy.PermissionSnapshot(ctx, PrincipalServicePrincipal, scope.PrincipalID)
		if err != nil {
			return AccessDecision{}, err
		}
		if snapshot.Mode == "v2" {
			query := PermissionQuery{
				Action: machinePermissionAction(action), Scope: ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.AgentInstanceID},
				ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Object: object,
			}
			decision, err := policy.ResolvePermission(ctx, PrincipalServicePrincipal, scope.PrincipalID, query)
			if err != nil || object != nil || action == "run" || decision.Reason != "EXPLICIT_DENY" {
				return AccessDecision{Allowed: decision.Allowed, Reason: decision.Reason}, err
			}
			if object == nil {
				// This gate qualifies an action, not a particular Run. An object
				// deny must be checked against the durable object below, rather
				// than making every other Run unavailable at token exchange.
				// ResolvePermission above must first verify active organization
				// scope. Reload after it so an object-deny qualification never
				// ignores a newer disabled principal or organization-wide deny.
				snapshot, err = policy.PermissionSnapshot(ctx, PrincipalServicePrincipal, scope.PrincipalID)
				if err != nil {
					return AccessDecision{}, err
				}
				if snapshot.Mode != "v2" {
					return AccessDecision{}, ErrInvalidResource
				}
				grants := make([]Grant, 0, len(snapshot.Grants))
				for _, grant := range snapshot.Grants {
					if action != "run" && grant.Effect == "deny" && grant.DataScope.Validate() == nil && grant.DataScope.Type != "approved_organization" {
						continue
					}
					grants = append(grants, grant)
				}
				snapshot.Grants = grants
				query.Now = time.Now().UTC()
				decision, err := EvaluatePermission(snapshot, query)
				return AccessDecision{Allowed: decision.Allowed, Reason: decision.Reason}, err
			}
			return AccessDecision{Allowed: decision.Allowed, Reason: decision.Reason}, err
		}
		if snapshot.Mode != "legacy" && snapshot.Mode != "shadow" {
			return AccessDecision{}, ErrInvalidResource
		}
	}
	return CheckPrincipalAccess(ctx, store, scope, PrincipalServicePrincipal, scope.PrincipalID, action)
}

// AuthorizeMachineRunToken receives only the execution repository's durable
// Run scope. Public callers cannot supply an owner or a data-scope object.
func (m *Module) AuthorizeMachineRunToken(ctx context.Context, rawToken, remoteAddr, action string, runScope sharedkernel.Scope, runID string) error {
	verified, err := m.AuthenticateMachineToken(ctx, rawToken, remoteAddr, action)
	if err != nil {
		return err
	}
	scope := verified.Scope
	if action == "run" || strings.TrimSpace(runID) != runID || runID == "" || runScope.RunID != runID ||
		runScope.PrincipalType != scope.PrincipalType || runScope.PrincipalID != scope.PrincipalID ||
		runScope.TenantID != scope.TenantID || runScope.DepartmentID != scope.DepartmentID ||
		runScope.ApplicationID != scope.ApplicationID || runScope.AgentInstanceID != scope.AgentInstanceID {
		return ErrMachineAccessDenied
	}
	object := DataObject{ID: runID, OwnerID: runScope.PrincipalID, ActorID: runScope.PrincipalID,
		Scope: ManagementScope{Type: "application", TenantID: runScope.TenantID, DepartmentID: runScope.DepartmentID, ApplicationID: runScope.ApplicationID}}
	decision, err := checkMachinePermission(ctx, m.store, scope, action, &object)
	if err != nil || !decision.Allowed {
		return ErrMachineAccessDenied
	}
	return nil
}
