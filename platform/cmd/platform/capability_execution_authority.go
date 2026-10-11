package main

import (
	"context"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type capabilityExecutionAuthority struct {
	ancestry               func(context.Context, sharedkernel.Scope) error
	isDelegatedBusinessRun func(context.Context, sharedkernel.Scope) bool
	execution              interface {
		ValidateLiveLease(context.Context, sharedkernel.Scope, string, string, string) error
		RenewCapabilityToken(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	}
	identity identity.AuthorizationVersionPort
	catalog  interface {
		ResolveEvaluationAgentTarget(context.Context, sharedkernel.Scope, string, string) (catalog.EvaluationAgentTarget, error)
	}
}

func (a capabilityExecutionAuthority) AuthorizeCapability(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string) error {
	if a.execution == nil || a.identity == nil || a.catalog == nil {
		return errors.New("execution authority unavailable")
	}
	if err := a.execution.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
		return err
	}
	if scope.ParentRunID != "" {
		if a.ancestry == nil {
			return errors.New("delegated execution ancestry denied")
		}
		// A joined or independent ancestry read can still wait on a live parent
		// row. That wait is retried by budget admission; rewriting it here is
		// what made the child ledger a scope mismatch with no SQLSTATE.
		if err := a.ancestry(ctx, scope); err != nil {
			if ancestryLockWait(err) {
				return err
			}
			return errors.New("delegated execution ancestry denied")
		}
	} else if a.ancestry != nil {
		if err := a.ancestry(ctx, scope); err != nil {
			return err
		}
	}
	action := "run"
	if classifier, ok := a.execution.(interface {
		CapabilityAuthorizationAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	}); ok {
		var err error
		action, err = classifier.CapabilityAuthorizationAction(ctx, scope, operation, bodyHash, policyHash)
		if err != nil || (action != "run" && action != "policy.manage") {
			return errors.New("execution authorization action denied")
		}
	}
	// Delegated business children do not receive a user run grant on the target
	// installation. Their trusted ancestry guard validates the persisted exact
	// edge, root caller epoch, root/target machine epochs and current delegate
	// grants. Management actions retain the ordinary local epoch boundary.
	delegatedRun := scope.ParentRunID != "" && action == "run" && a.isDelegatedBusinessRun != nil && a.isDelegatedBusinessRun(ctx, scope)
	if !delegatedRun {
		epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, action)
		if err != nil || epoch != scope.AuthorizationEpoch {
			return errors.New("current IAM authorization denied")
		}
	}
	target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
	if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
		return errors.New("current installation denied")
	}
	return nil
}

// AuthorizeStopOnlyExecution proves that the signed capability belongs to the
// current parent Run command. IAM and catalog permissions are intentionally
// checked by neither this method nor the stop-only transaction: cancellation
// acts only on an already persisted child edge.
func (a capabilityExecutionAuthority) AuthorizeStopOnlyExecution(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string, lease sharedkernel.ExecutionLeaseBinding) error {
	if a.execution == nil || scope.ValidateTrusted() != nil || lease.Revision == 0 || len(lease.TokenHash) != 64 {
		return errors.New("stop-only execution authority unavailable")
	}
	ctx = sharedkernel.WithExecutionLease(ctx, lease)
	if classifier, ok := a.execution.(interface {
		CapabilityAuthorizationAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	}); ok {
		action, err := classifier.CapabilityAuthorizationAction(ctx, scope, operation, bodyHash, policyHash)
		if err != nil || action != "run" {
			return errors.New("stop-only execution command denied")
		}
		return nil
	}
	return errors.New("stop-only execution classifier unavailable")
}

func (a capabilityExecutionAuthority) RenewCapability(ctx context.Context, scope sharedkernel.Scope, op, body, policy string) (string, error) {
	if err := a.AuthorizeCapability(ctx, scope, op, body, policy); err != nil {
		return "", err
	}
	return a.execution.RenewCapabilityToken(ctx, scope, op, body, policy)
}

func (a capabilityExecutionAuthority) AuthorizeCurrentRunEpoch(ctx context.Context, scope sharedkernel.Scope) error {
	if scope.ParentRunID != "" && a.isDelegatedBusinessRun != nil && a.isDelegatedBusinessRun(ctx, scope) {
		if a.ancestry == nil {
			return errors.New("delegated execution authority unavailable")
		}
		return a.ancestry(ctx, scope)
	}
	if a.identity == nil {
		return errors.New("execution authority unavailable")
	}
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, "run")
	if err != nil || epoch != scope.AuthorizationEpoch {
		return errors.New("current IAM authorization denied")
	}
	return nil
}

func (a capabilityExecutionAuthority) AuthorizeCapabilityResource(ctx context.Context, scope sharedkernel.Scope, access capability.CapabilityResourceAccess) error {
	snapshots, ok := a.identity.(interface {
		PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error)
	})
	if !ok {
		return errors.New("capability IAM unavailable")
	}
	snapshot, err := snapshots.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil {
		return err
	}
	// Legacy instances retain their existing execution/published-policy checks
	// until the explicit migration enables v2; unknown modes fail closed.
	if snapshot.Mode == "legacy" || snapshot.Mode == "shadow" {
		return nil
	}
	if snapshot.Mode != "v2" {
		return identity.ErrPermissionDenied
	}
	target := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}
	decision, err := identity.EvaluatePermission(capabilityResourceEligibility(snapshot, access), identity.PermissionQuery{Action: access.Action, Scope: target, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return identity.ErrPermissionDenied
	}
	resolver, ok := a.identity.(identity.WorkloadIdentityResolver)
	if !ok {
		return errors.New("workload identity resolver unavailable")
	}
	binding, err := resolver.ResolveWorkloadIdentity(ctx, scope)
	if err != nil {
		return err
	}
	if binding.Status != "active" || binding.Revision == 0 || binding.PrincipalID == "" || binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID || binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID || binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID {
		return identity.ErrPermissionDenied
	}
	credentials, ok := a.identity.(interface {
		GetMachineCredential(context.Context, string, string) (identity.MachineCredential, error)
	})
	if !ok {
		return errors.New("workload credential authority unavailable")
	}
	credential, err := credentials.GetMachineCredential(ctx, scope.TenantID, binding.PrincipalID)
	if err != nil {
		return err
	}
	if credential.Status != "active" || credential.Revision == 0 || credential.TenantID != scope.TenantID || credential.PrincipalID != binding.PrincipalID {
		return identity.ErrPermissionDenied
	}
	executor, err := snapshots.PermissionSnapshot(ctx, identity.PrincipalServicePrincipal, binding.PrincipalID)
	if err != nil {
		return err
	}
	if executor.Mode != "v2" || executor.Principal.Type != identity.PrincipalServicePrincipal || executor.Principal.ID != binding.PrincipalID {
		return identity.ErrPermissionDenied
	}
	decision, err = identity.EvaluatePermission(capabilityResourceEligibility(executor, access), identity.PermissionQuery{Action: access.Action, Scope: target, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Now: time.Now().UTC()})
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return identity.ErrPermissionDenied
	}
	return nil
}
