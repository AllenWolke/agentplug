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
	return a.authorizeCapability(ctx, scope, operation, bodyHash, policyHash, nil)
}

// One live fence reuses only the caller facts read within that very fence.
// Subsequent provider/State fences execute the whole check again.
func (a capabilityExecutionAuthority) AuthorizeCapabilityAndResource(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string, access capability.CapabilityResourceAccess) (string, error) {
	stage := "RUN_AUTHORITY"
	var authorized authorizedResourceSnapshots
	err := a.authorizeCapability(ctx, scope, operation, bodyHash, policyHash, func(readCtx context.Context, caller *identity.PermissionSnapshot) error {
		stage = "RESOURCE_AUTHORITY"
		var err error
		authorized, err = a.authorizedResourceSnapshotsWithCaller(readCtx, scope, access, caller)
		return err
	})
	if err == nil {
		epoch := capability.CapabilityAdmissionEpoch(ctx)
		if facts := capability.NewCapabilityAdmissionFacts(scope, epoch, authorized.caller,
			authorized.executor, authorized.binding, authorized.credential); facts != nil {
			capability.CaptureCapabilityAdmissionFacts(ctx, facts)
		}
	}
	return stage, err
}

func (a capabilityExecutionAuthority) authorizeCapability(ctx context.Context, scope sharedkernel.Scope, operation, bodyHash, policyHash string,
	resource func(context.Context, *identity.PermissionSnapshot) error) error {
	if a.execution == nil || a.identity == nil || a.catalog == nil {
		return errors.New("execution authority unavailable")
	}
	action := "run"
	combined, combinedOK := a.execution.(interface {
		ValidateLiveLeaseAndAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	})
	if combinedOK {
		var err error
		action, err = combined.ValidateLiveLeaseAndAction(ctx, scope, operation, bodyHash, policyHash)
		if ancestryLockWait(err) {
			return err
		}
		if err != nil || (action != "run" && action != "policy.manage") {
			return errors.New("execution authorization action denied")
		}
	} else if err := a.execution.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
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
	if classifier, ok := a.execution.(interface {
		CapabilityAuthorizationAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	}); ok && !combinedOK {
		var err error
		action, err = classifier.CapabilityAuthorizationAction(ctx, scope, operation, bodyHash, policyHash)
		if ancestryLockWait(err) {
			return err
		}
		if err != nil || (action != "run" && action != "policy.manage") {
			return errors.New("execution authorization action denied")
		}
	}
	// Delegated business children do not receive a user run grant on the target
	// installation. Their trusted ancestry guard validates the persisted exact
	// edge, root caller epoch, root/target machine epochs and current delegate
	// grants. Management actions retain the ordinary local epoch boundary.
	delegatedRun := scope.ParentRunID != "" && action == "run" && a.isDelegatedBusinessRun != nil && a.isDelegatedBusinessRun(ctx, scope)
	finish := func(readCtx context.Context, snapshot *identity.PermissionSnapshot) error {
		if action == "run" {
			if pinned, ok := a.execution.(interface {
				ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error
			}); ok {
				if err := pinned.ValidatePinnedRunTarget(readCtx, scope); err != nil {
					return err
				}
				if resource != nil {
					return resource(readCtx, snapshot)
				}
				return nil
			}
		}
		target, err := a.catalog.ResolveEvaluationAgentTarget(readCtx, scope, scope.AgentID, scope.AgentVersionID)
		if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
			return errors.New("current installation denied")
		}
		if resource != nil {
			return resource(readCtx, snapshot)
		}
		return nil
	}
	if !delegatedRun {
		expected, proofErr := expectedExecutionEpoch(ctx, a.execution, scope)
		if ancestryLockWait(proofErr) {
			return proofErr
		}
		if proofErr != nil {
			return errors.New("current IAM authorization denied")
		}
		if joined, ok := a.identity.(interface {
			WithCurrentAuthorizationSnapshotContext(context.Context, sharedkernel.Scope, string,
				func(context.Context, uint64, identity.PermissionSnapshot) error) error
		}); ok && resource != nil {
			return joined.WithCurrentAuthorizationSnapshotContext(ctx, scope, action,
				func(readCtx context.Context, epoch uint64, snapshot identity.PermissionSnapshot) error {
					if epoch != expected {
						return errors.New("current IAM authorization denied")
					}
					if err := finish(readCtx, &snapshot); err != nil {
						return err
					}
					capability.CaptureCapabilityAdmissionEpoch(ctx, epoch)
					return nil
				})
		}
		if joined, ok := a.identity.(interface {
			WithCurrentAuthorizationSnapshot(context.Context, sharedkernel.Scope, string, func(uint64, identity.PermissionSnapshot) error) error
		}); ok && resource != nil {
			return joined.WithCurrentAuthorizationSnapshot(ctx, scope, action, func(epoch uint64, snapshot identity.PermissionSnapshot) error {
				if epoch != expected {
					return errors.New("current IAM authorization denied")
				}
				if err := finish(ctx, &snapshot); err != nil {
					return err
				}
				capability.CaptureCapabilityAdmissionEpoch(ctx, epoch)
				return nil
			})
		}
		epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, action)
		if ancestryLockWait(err) {
			return err
		}
		if err != nil || epoch != expected {
			return errors.New("current IAM authorization denied")
		}
	}
	// Only business Runs have a persisted Agent HTTP endpoint. An internal
	// index command was classified from its verified durable lease above and
	// retains management IAM plus the exact current catalog target checks.
	return finish(ctx, nil)
}

// RecheckCapabilityAndResource is the post-provider/state fence for the same
// HTTP request. It refreshes mutable run/lease, ancestry, catalog and caller IAM
// epoch facts, then reuses only the caller snapshot while that caller epoch is
// unchanged. Executor permissions, workload binding and machine credential are
// read again because their own revisions are not represented by the caller's
// action-scoped IAM epoch. The capability layer also reauthenticates the
// presented workload proof before disclosure/commit.
func (a capabilityExecutionAuthority) RecheckCapabilityAndResource(ctx context.Context, scope sharedkernel.Scope,
	operation, bodyHash, policyHash string, access capability.CapabilityResourceAccess,
	facts *capability.CapabilityAdmissionFacts) error {
	if a.execution == nil || a.identity == nil || a.catalog == nil || facts == nil || access.Action == "" {
		return errors.New("request-scoped authorization facts unavailable")
	}
	factScope, factEpoch, caller, executor, binding, credential, ok := facts.SnapshotValues()
	if !ok || factScope != scope || factEpoch != scope.AuthorizationEpoch ||
		caller.Principal.ID != scope.PrincipalID || caller.Principal.Type != identity.PrincipalType(scope.PrincipalType) ||
		caller.Principal.TenantID != scope.TenantID || executor.Principal.Type != identity.PrincipalServicePrincipal ||
		executor.Principal.ID != binding.PrincipalID || executor.Principal.TenantID != scope.TenantID ||
		binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID ||
		binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID ||
		binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID ||
		binding.Status != "active" || binding.Revision == 0 || credential.TenantID != scope.TenantID ||
		credential.PrincipalID != binding.PrincipalID || credential.Status != "active" || credential.Revision == 0 {
		return errors.New("request-scoped authorization facts mismatch")
	}
	action := "run"
	combined, combinedOK := a.execution.(interface {
		ValidateLiveLeaseAndAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	})
	if combinedOK {
		var err error
		action, err = combined.ValidateLiveLeaseAndAction(ctx, scope, operation, bodyHash, policyHash)
		if ancestryLockWait(err) {
			return err
		}
		if err != nil || (action != "run" && action != "policy.manage") {
			return errors.New("execution authorization action denied")
		}
	} else if err := a.execution.ValidateLiveLease(ctx, scope, operation, bodyHash, policyHash); err != nil {
		return err
	}
	if classifier, ok := a.execution.(interface {
		CapabilityAuthorizationAction(context.Context, sharedkernel.Scope, string, string, string) (string, error)
	}); ok && !combinedOK {
		classified, err := classifier.CapabilityAuthorizationAction(ctx, scope, operation, bodyHash, policyHash)
		if ancestryLockWait(err) {
			return err
		}
		if err != nil || (classified != "run" && classified != "policy.manage") || classified != action {
			return errors.New("execution authorization action denied")
		}
	}
	if scope.ParentRunID != "" {
		if a.ancestry == nil {
			return errors.New("delegated execution ancestry denied")
		}
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
	if scope.ParentRunID != "" && action == "run" && a.isDelegatedBusinessRun != nil && a.isDelegatedBusinessRun(ctx, scope) {
		// Delegated business authorization has a distinct trusted ancestry/IAM
		// contract; keep its established full-check path rather than reusing
		// snapshots governed by the ordinary local epoch.
		return a.authorizeCapability(ctx, scope, operation, bodyHash, policyHash, func(readCtx context.Context, caller *identity.PermissionSnapshot) error {
			_, err := a.authorizedResourceSnapshotsWithCaller(readCtx, scope, access, caller)
			return err
		})
	}
	expected, err := expectedExecutionEpoch(ctx, a.execution, scope)
	if ancestryLockWait(err) {
		return err
	}
	if err != nil || expected != factEpoch {
		return errors.New("current IAM authorization denied")
	}
	if action == "run" {
		if pinned, ok := a.execution.(interface {
			ValidatePinnedRunTarget(context.Context, sharedkernel.Scope) error
		}); ok {
			if err := pinned.ValidatePinnedRunTarget(ctx, scope); err != nil {
				return err
			}
		} else {
			target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
			if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
				return errors.New("current installation denied")
			}
		}
	} else {
		target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
		if err != nil || target.InstallationID != scope.InstallationID || target.AgentVersionID != scope.AgentVersionID {
			return errors.New("current installation denied")
		}
	}
	// Refresh the caller snapshot under the same continuity lock that validates
	// its epoch, then check executor grants, binding and credential in that same
	// transaction. Reusing the request-entry caller snapshot after a separate
	// epoch read would leave a revocation race between the two operations.
	if joined, ok := a.identity.(interface {
		WithCurrentAuthorizationSnapshotContext(context.Context, sharedkernel.Scope, string,
			func(context.Context, uint64, identity.PermissionSnapshot) error) error
	}); ok {
		return joined.WithCurrentAuthorizationSnapshotContext(ctx, scope, action,
			func(readCtx context.Context, epoch uint64, currentCaller identity.PermissionSnapshot) error {
				if epoch != factEpoch {
					return errors.New("current IAM authorization denied")
				}
				_, err := a.authorizedResourceSnapshotsWithCaller(readCtx, scope, access, &currentCaller)
				return err
			})
	}
	// Older adapters fail closed through fresh reads rather than reusing the
	// request-entry snapshot. Production SQLStore implements the fenced path.
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, action)
	if ancestryLockWait(err) {
		return err
	}
	if err != nil || epoch != factEpoch {
		return errors.New("current IAM authorization denied")
	}
	_, err = a.authorizedResourceSnapshots(ctx, scope, access)
	return err
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
	expected, proofErr := expectedExecutionEpoch(ctx, a.execution, scope)
	if ancestryLockWait(proofErr) {
		return proofErr
	}
	epoch, err := a.identity.CurrentAuthorizationEpoch(ctx, scope, "run")
	if ancestryLockWait(err) {
		return err
	}
	if proofErr != nil || err != nil || epoch != expected {
		return errors.New("current IAM authorization denied")
	}
	return nil
}

func (a capabilityExecutionAuthority) AuthorizeCapabilityResource(ctx context.Context, scope sharedkernel.Scope, access capability.CapabilityResourceAccess) error {
	_, err := a.authorizedResourceSnapshots(ctx, scope, access)
	return err
}

type authorizedResourceSnapshots struct {
	caller     identity.PermissionSnapshot
	executor   identity.PermissionSnapshot
	binding    identity.WorkloadBinding
	credential identity.MachineCredential
}

// One resource check supplies the same freshly read snapshots to its immediate
// document filter. This is not an authorization cache: every invocation reloads
// IAM, binding and credential state; retrieval's before/after fences still call
// it independently. No snapshot is retained across a source/model operation.
func (a capabilityExecutionAuthority) authorizedResourceSnapshots(ctx context.Context, scope sharedkernel.Scope, access capability.CapabilityResourceAccess) (authorizedResourceSnapshots, error) {
	return a.authorizedResourceSnapshotsWithCaller(ctx, scope, access, nil)
}

func (a capabilityExecutionAuthority) authorizedResourceSnapshotsWithCaller(ctx context.Context, scope sharedkernel.Scope, access capability.CapabilityResourceAccess, caller *identity.PermissionSnapshot) (authorizedResourceSnapshots, error) {
	empty := authorizedResourceSnapshots{}
	snapshots, ok := a.identity.(interface {
		PermissionSnapshot(context.Context, identity.PrincipalType, string) (identity.PermissionSnapshot, error)
	})
	if !ok {
		return empty, errors.New("capability IAM unavailable")
	}
	var snapshot identity.PermissionSnapshot
	var err error
	if caller != nil {
		if caller.Principal.ID != scope.PrincipalID || string(caller.Principal.Type) != scope.PrincipalType || caller.Principal.TenantID != scope.TenantID {
			return empty, identity.ErrPermissionDenied
		}
		snapshot = *caller
	} else {
		snapshot, err = snapshots.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
		if err != nil {
			return empty, err
		}
	}
	// Legacy instances retain their existing execution/published-policy checks
	// until the explicit migration enables v2; unknown modes fail closed.
	if snapshot.Mode == "legacy" || snapshot.Mode == "shadow" {
		return authorizedResourceSnapshots{caller: snapshot}, nil
	}
	if snapshot.Mode != "v2" {
		return empty, identity.ErrPermissionDenied
	}
	target := identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID}
	decision, err := identity.EvaluatePermission(capabilityResourceEligibility(snapshot, access), identity.PermissionQuery{Action: access.Action, Scope: target, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Now: time.Now().UTC()})
	if err != nil {
		return empty, err
	}
	if !decision.Allowed {
		return empty, identity.ErrPermissionDenied
	}
	resolver, ok := a.identity.(identity.WorkloadIdentityResolver)
	if !ok {
		return empty, errors.New("workload identity resolver unavailable")
	}
	binding, err := resolver.ResolveWorkloadIdentity(ctx, scope)
	if err != nil {
		return empty, err
	}
	if binding.Status != "active" || binding.Revision == 0 || binding.PrincipalID == "" || binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID || binding.ApplicationID != scope.ApplicationID || binding.InstallationID != scope.InstallationID || binding.AgentID != scope.AgentID || binding.AgentVersionID != scope.AgentVersionID {
		return empty, identity.ErrPermissionDenied
	}
	credentials, ok := a.identity.(interface {
		GetMachineCredential(context.Context, string, string) (identity.MachineCredential, error)
	})
	if !ok {
		return empty, errors.New("workload credential authority unavailable")
	}
	credential, err := credentials.GetMachineCredential(ctx, scope.TenantID, binding.PrincipalID)
	if err != nil {
		return empty, err
	}
	if credential.Status != "active" || credential.Revision == 0 || credential.TenantID != scope.TenantID || credential.PrincipalID != binding.PrincipalID {
		return empty, identity.ErrPermissionDenied
	}
	executor, err := snapshots.PermissionSnapshot(ctx, identity.PrincipalServicePrincipal, binding.PrincipalID)
	if err != nil {
		return empty, err
	}
	if executor.Mode != "v2" || executor.Principal.Type != identity.PrincipalServicePrincipal || executor.Principal.ID != binding.PrincipalID {
		return empty, identity.ErrPermissionDenied
	}
	decision, err = identity.EvaluatePermission(capabilityResourceEligibility(executor, access), identity.PermissionQuery{Action: access.Action, Scope: target, ResourceType: access.ResourceType, ResourceID: access.ResourceID, Now: time.Now().UTC()})
	if err != nil {
		return empty, err
	}
	if !decision.Allowed {
		return empty, identity.ErrPermissionDenied
	}
	return authorizedResourceSnapshots{caller: snapshot, executor: executor, binding: binding, credential: credential}, nil
}
