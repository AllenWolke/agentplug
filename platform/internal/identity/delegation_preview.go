package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type DelegationPreview struct {
	RequestDigest string            `json:"request_digest"`
	StepUpAction  string            `json:"step_up_action"`
	Command       DelegationCommand `json:"change"`
	Delegation    Delegation        `json:"delegation"`
}

// The same semantic validation runs before fresh authentication and again in
// the committing transaction. Preview never consumes a proof or grants rights.
func (s *SQLStore) validateDelegationTarget(ctx context.Context, reader permissionReader, target PermissionSnapshot, command DelegationCommand, now time.Time) (Delegation, error) {
	if command.Delegation == nil {
		for _, delegation := range target.Delegations {
			if delegation.ID == command.RevokeDelegationID && delegation.Status == "active" {
				return delegation, nil
			}
		}
		return Delegation{}, ErrInvalidResource
	}
	delegation := *command.Delegation
	if err := validateDelegationBoundary(delegation, target, now); err != nil {
		return Delegation{}, err
	}
	if err := validatePermissionScope(ctx, reader, delegation.Scope); err != nil {
		return Delegation{}, err
	}
	for _, resource := range delegation.Resources {
		if s.permissionResourceResolver == nil {
			return Delegation{}, ErrPermissionDenied
		}
		if _, err := s.permissionResourceResolver.ResolveAgentInstallation(ctx, sharedkernel.Scope{TenantID: delegation.Scope.TenantID, DepartmentID: delegation.Scope.DepartmentID, ApplicationID: delegation.Scope.ApplicationID}, resource); err != nil {
			return Delegation{}, err
		}
		resourceScope := ManagementScope{Type: "agent_installation", TenantID: delegation.Scope.TenantID, DepartmentID: delegation.Scope.DepartmentID, ApplicationID: delegation.Scope.ApplicationID, ResourceID: resource}
		if !delegation.Scope.Contains(resourceScope) {
			return Delegation{}, ErrScopeMismatch
		}
	}
	for _, binding := range delegation.ResourceBindings {
		grant := Grant{SubjectType: PrincipalUser, SubjectID: delegation.SubjectID, TenantID: delegation.Scope.TenantID, DepartmentID: delegation.Scope.DepartmentID, ApplicationID: delegation.Scope.ApplicationID, AgentInstanceID: binding.InstallationID, ResourceType: binding.ResourceType, ResourceID: binding.ResourceID}
		if err := s.validateGrantResource(ctx, grant); err != nil {
			return Delegation{}, err
		}
		installationScope := ManagementScope{Type: "agent_installation", TenantID: grant.TenantID, DepartmentID: grant.DepartmentID, ApplicationID: grant.ApplicationID, ResourceID: grant.AgentInstanceID}
		if !delegation.Scope.Contains(installationScope) {
			return Delegation{}, ErrScopeMismatch
		}
	}
	return delegation, nil
}

func (s *SQLStore) PreviewDelegation(ctx context.Context, actor sharedkernel.Scope, command DelegationCommand) (DelegationPreview, error) {
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return DelegationPreview{}, ErrPermissionDenied
	}
	command.StepUpToken = ""
	// Own nested collections so normalizing or rendering a plan cannot mutate a
	// caller's subsequent operation while retaining its old authentication digest.
	raw, err := json.Marshal(command)
	if err != nil {
		return DelegationPreview{}, err
	}
	var owned DelegationCommand
	if err := json.Unmarshal(raw, &owned); err != nil {
		return DelegationPreview{}, err
	}
	command = owned
	if err := validateDelegationCommand(command); err != nil {
		return DelegationPreview{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DelegationPreview{}, err
	}
	defer tx.Rollback()
	owner, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		return DelegationPreview{}, err
	}
	if owner.Principal.TenantID != actor.TenantID {
		return DelegationPreview{}, ErrScopeMismatch
	}
	now := s.clock().UTC().Truncate(time.Microsecond)
	if err := requireAdministrativeStepUp(owner, "delegation.manage", actor.TenantID, now); err != nil {
		return DelegationPreview{}, err
	}
	target, err := loadPermissionSnapshot(ctx, tx, PrincipalUser, command.SubjectID)
	if err != nil {
		return DelegationPreview{}, err
	}
	if target.Mode != "v2" || !target.Principal.IsActive {
		return DelegationPreview{}, ErrPermissionDenied
	}
	if target.Principal.Revision != command.ExpectedRevision {
		return DelegationPreview{}, ErrIdentityConflict
	}
	delegation, err := s.validateDelegationTarget(ctx, tx, target, command, now)
	if err != nil {
		return DelegationPreview{}, err
	}
	if err := authorizeCompanyDelegation(owner, target, delegation, command.Delegation != nil, now); err != nil {
		return DelegationPreview{}, err
	}
	digest, err := DelegationCommandDigest(command)
	if err != nil {
		return DelegationPreview{}, err
	}
	if err := tx.Commit(); err != nil {
		return DelegationPreview{}, err
	}
	return DelegationPreview{RequestDigest: digest, StepUpAction: "delegation.manage", Command: command, Delegation: delegation}, nil
}

type DelegationPreviewRepository interface {
	PreviewDelegation(context.Context, sharedkernel.Scope, DelegationCommand) (DelegationPreview, error)
}
