package main

import (
	"context"
	"database/sql"
	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// The trusted dispatcher finalizes without an HTTP capability context. Its
// transaction instead proves actual Run/session lease, frozen policy and live
// dual authority explicitly; public route admission keeps its token boundary.
func (a agentRouteAuthority) GroupWaitFenceTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if a.identity == nil || a.runs == nil || tx == nil || scope.ValidateTrusted() != nil {
		return agentcoordination.ErrDenied
	}
	if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	return lockBudgetAncestors(ctx, tx, a.runs, scope)
}

func (a agentRouteAuthority) ParentForGroupWaitTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (agentcoordination.ParentFacts, error) {
	empty := agentcoordination.ParentFacts{}
	if a.identity == nil || a.runs == nil || a.catalog == nil || a.routes == nil || tx == nil || a.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return empty, agentcoordination.ErrDenied
	}
	run, err := a.runs.BudgetRunTx(ctx, tx, scope.RunID)
	if err != nil {
		return empty, err
	}
	if run.Scope != scope || a.runs.CheckLiveRunTx(ctx, tx, scope) != nil {
		return empty, agentcoordination.ErrDenied
	}
	command, policy, err := budgetRunPolicy(ctx, tx, run)
	if err != nil {
		return empty, err
	}
	if policy.Runtime.Delegation == nil || policy.Runtime.Delegation.Validate() != nil {
		return empty, agentcoordination.ErrDenied
	}
	principal, err := a.identity.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil || principal.Mode != "v2" {
		return empty, agentcoordination.ErrDenied
	}
	for _, action := range []string{"agent.delegate"} {
		if scope.ParentRunID == "" && action == "agent.delegate" {
			if a.resources.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{Action: "run", ResourceType: "agent_installation", ResourceID: scope.InstallationID}) != nil {
				return empty, agentcoordination.ErrDenied
			}
		}
		if a.resources.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{Action: action, ResourceType: "agent_installation", ResourceID: scope.InstallationID}) != nil {
			return empty, agentcoordination.ErrDenied
		}
	}
	if scope.ParentRunID != "" && (coordinatedAncestryGuard{route: a}).CheckTx(ctx, tx, scope) != nil {
		return empty, agentcoordination.ErrDenied
	}
	facts := agentcoordination.ParentFacts{Scope: scope, PolicyHash: policy.Hash, Policy: policy.Runtime.Delegation, Depth: int(command.Scope.DelegationDepth), Active: true}
	parentID := scope.ParentRunID
	for remaining := facts.Depth; remaining > 0; remaining-- {
		ancestor, err := a.runs.BudgetRunTx(ctx, tx, parentID)
		if err != nil {
			return empty, err
		}
		facts.AncestorAgentIDs = append(facts.AncestorAgentIDs, ancestor.Scope.AgentID)
		facts.AncestorInstallations = append(facts.AncestorInstallations, ancestor.Scope.InstallationID)
		parentID = ancestor.Scope.ParentRunID
	}
	if parentID != "" {
		return empty, agentcoordination.ErrDenied
	}
	return facts, nil
}

// This checks execution continuity only. Every caller must retain its current
// dual IAM, original delegation policy, target and ancestor checks. A waiting
// parent gains neither a live execution lease nor new child-admission rights.
func (a agentRouteAuthority) checkActiveParentChildTx(ctx context.Context, tx *sql.Tx, parent execution.BudgetRunFacts, child sharedkernel.Scope, depth int) error {
	if a.runs == nil || a.routes == nil {
		return agentcoordination.ErrDenied
	}
	switch parent.Status {
	case platformruntime.StatusRunning:
		return a.runs.CheckLiveRunTx(ctx, tx, parent.Scope)
	case platformruntime.StatusWaiting:
		ref, err := a.runs.CurrentAgentGroupWaitTx(ctx, tx, parent.Scope)
		if err != nil {
			return err
		}
		return a.routes.CheckWaitingGroupChildTx(ctx, tx, parent.Scope, child, depth, ref.Handoff)
	default:
		return agentcoordination.ErrDenied
	}
}

// Retention is current dual authorization, never just a historical receipt.
// It accepts no outputs and cannot create another child or renew the parent.
func (a agentRouteAuthority) canRetainWaitingChildTx(ctx context.Context, tx *sql.Tx, parent, child execution.BudgetRunFacts, depth int) bool {
	ctx = withEpochMemo(ctx, tx)
	if parent.Status != platformruntime.StatusWaiting || a.checkActiveParentChildTx(ctx, tx, parent, child.Scope, depth) != nil {
		return false
	}
	command, policy, err := budgetRunPolicy(ctx, tx, parent)
	if err != nil || int(command.Scope.DelegationDepth)+1 != depth {
		return false
	}
	delegation := policy.Runtime.Delegation
	if delegation == nil || delegation.Validate() != nil || depth > delegation.MaxDepth {
		return false
	}
	binding, err := a.routes.ChildRoutingFactsTx(ctx, tx, parent.Scope, child.Scope, depth)
	if err != nil || binding.PolicyHash != policy.Hash || binding.RequestFingerprint != child.RequestFingerprint || !delegatedContains(delegation.AllowedAgentIDs, child.Scope.AgentID) || !delegatedContains(delegation.TaskTypes, binding.TaskType) {
		return false
	}
	if (parent.Scope.ParentRunID == "" && a.resources.AuthorizeCapabilityResource(ctx, parent.Scope, capability.CapabilityResourceAccess{Action: "run", ResourceType: "agent_installation", ResourceID: parent.Scope.InstallationID}) != nil) || a.resources.AuthorizeCapabilityResource(ctx, parent.Scope, capability.CapabilityResourceAccess{Action: "agent.delegate", ResourceType: "agent_installation", ResourceID: parent.Scope.InstallationID}) != nil || a.routeTargetAuthority(ctx, tx, parent.Scope, policy.Hash, binding.Target) != nil {
		return false
	}
	if parent.Scope.ParentRunID != "" && (coordinatedAncestryGuard{route: a}).CheckWaitingTx(ctx, tx, parent.Scope) != nil {
		return false
	}
	return true
}
