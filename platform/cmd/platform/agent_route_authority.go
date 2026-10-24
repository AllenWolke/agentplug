package main

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type agentRouteAuthority struct {
	routes    *agentcoordination.SQLRouteStore
	identity  *identity.SQLStore
	runs      *execution.SQLStore
	catalog   *catalog.Module
	resources capabilityExecutionAuthority
}

func (a agentRouteAuthority) Parent(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (agentcoordination.ParentFacts, error) {
	denied := func(reason agentcoordination.RouteDenialReason) (agentcoordination.ParentFacts, error) {
		return agentcoordination.ParentFacts{}, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialParent, reason, nil)
	}
	if a.identity == nil || a.runs == nil || a.catalog == nil || tx == nil {
		return denied(agentcoordination.RouteReasonParentUnavailable)
	}
	if a.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return denied(agentcoordination.RouteReasonParentIAMContinuity)
	}
	if err := lockBudgetAncestors(ctx, tx, a.runs, scope); err != nil {
		return denied(agentcoordination.RouteReasonParentAncestorBudget)
	}
	lease, policy, err := capability.AgentCoordinationAuthority(ctx, scope)
	if err != nil {
		if _, _, classified := agentcoordination.RouteErrorClassification(err); classified {
			return agentcoordination.ParentFacts{}, err
		}
		return denied(agentcoordination.RouteReasonParentLiveCheck)
	}
	if a.runs.CheckCapabilityLeaseTx(ctx, tx, scope, lease) != nil {
		return denied(agentcoordination.RouteReasonParentLease)
	}
	policyFacts, err := a.identity.PrincipalPolicyFactsTx(ctx, tx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil || policyFacts.Mode != "v2" {
		return denied(agentcoordination.RouteReasonParentPermissionMode)
	}
	if a.resources.AuthorizeCapabilityResource(ctx, scope, capability.CapabilityResourceAccess{Action: "agent.delegate", ResourceType: "agent_installation", ResourceID: scope.InstallationID}) != nil {
		return denied(agentcoordination.RouteReasonParentDelegate)
	}
	run, err := a.runs.GetContext(ctx, scope.RunID)
	if err != nil {
		return denied(agentcoordination.RouteReasonParentRunFacts)
	}
	if run.Scope != scope || run.Status != platformruntime.StatusRunning || len(run.RequestJSON) > 1<<20 {
		return denied(agentcoordination.RouteReasonParentRunFacts)
	}
	var command contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &command) != nil || command.Scope.RunID != scope.RunID || command.Scope.ParentRunID != scope.ParentRunID || command.Scope.DelegationDepth > 4 {
		return denied(agentcoordination.RouteReasonParentCommand)
	}
	facts := agentcoordination.ParentFacts{Scope: scope, PolicyHash: policy.Hash, Policy: policy.Runtime.Delegation, Depth: int(command.Scope.DelegationDepth), Active: true}
	seen := map[string]bool{scope.RunID: true}
	parentID := command.Scope.ParentRunID
	childScope := scope
	for remaining := facts.Depth; remaining > 0; remaining-- {
		if parentID == "" || seen[parentID] {
			return denied(agentcoordination.RouteReasonParentAncestry)
		}
		seen[parentID] = true
		ancestor, err := a.runs.GetContext(ctx, parentID)
		if err != nil || ancestor.Scope.ValidateTrusted() != nil || ancestor.Scope.TenantID != scope.TenantID || ancestor.Scope.DepartmentID != scope.DepartmentID || ancestor.Scope.ApplicationID != scope.ApplicationID || ancestor.Scope.PrincipalType != scope.PrincipalType || ancestor.Scope.PrincipalID != scope.PrincipalID || ancestor.Scope.SessionID != scope.SessionID || len(ancestor.RequestJSON) > 1<<20 {
			return denied(agentcoordination.RouteReasonParentAncestry)
		}
		ancestorFacts, err := a.runs.BudgetRunTx(ctx, tx, parentID)
		if err != nil || a.checkActiveParentChildTx(ctx, tx, ancestorFacts, childScope, remaining) != nil {
			return denied(agentcoordination.RouteReasonParentAncestry)
		}
		var input contract.ExecuteRequest
		if json.Unmarshal(ancestor.RequestJSON, &input) != nil || input.Scope.RunID != parentID || input.Scope.DelegationDepth != uint32(remaining-1) {
			return denied(agentcoordination.RouteReasonParentAncestry)
		}
		if a.routes == nil || a.routes.CheckChildEdgeTx(ctx, tx, ancestor.Scope, childScope, remaining) != nil {
			return denied(agentcoordination.RouteReasonParentAncestry)
		}
		facts.AncestorInstallations = append(facts.AncestorInstallations, ancestor.Scope.InstallationID)
		facts.AncestorAgentIDs = append(facts.AncestorAgentIDs, ancestor.Scope.AgentID)
		childScope = ancestor.Scope
		parentID = input.Scope.ParentRunID
	}
	if parentID != "" {
		return denied(agentcoordination.RouteReasonParentAncestry)
	}
	return facts, nil
}
func routeTarget(scope sharedkernel.Scope, value catalog.BusinessRouteTarget) agentcoordination.Target {
	return agentcoordination.Target{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: value.AgentID, InstallationID: value.InstallationID, InstallationRevision: value.InstallationRevision, VersionID: value.VersionID, DeploymentID: value.DeploymentID, DeploymentRevision: value.DeploymentRevision, ManifestHash: value.ManifestHash, InputSchema: value.InputSchemaURI, OutputSchema: value.OutputSchemaURI, TaskTypes: append([]string(nil), value.TaskTypes...), Published: true, Ready: true}
}
func (a agentRouteAuthority) Candidates(ctx context.Context, tx *sql.Tx, parent agentcoordination.ParentFacts, task string) ([]agentcoordination.Target, error) {
	if tx == nil || parent.Policy == nil {
		return nil, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialCandidates, agentcoordination.RouteReasonCandidateCatalog, agentcoordination.ErrDenied)
	}
	values, err := a.catalog.BusinessRouteCandidates(ctx, parent.Scope, parent.Policy.AllowedAgentIDs, task)
	if err != nil {
		return nil, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialCandidates, agentcoordination.RouteReasonCandidateCatalog, agentcoordination.ErrUnavailable)
	}
	result := make([]agentcoordination.Target, 0, len(values))
	for _, value := range values {
		result = append(result, routeTarget(parent.Scope, value))
	}
	return result, nil
}
func (a agentRouteAuthority) AuthorizeTarget(ctx context.Context, tx *sql.Tx, parent agentcoordination.ParentFacts, target agentcoordination.Target) error {
	if tx == nil || a.identity == nil {
		return agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetAuthority, nil)
	}
	if a.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetAuthority, agentcoordination.ErrDenied)
	}
	current, err := a.catalog.ResolveBusinessRouteTarget(ctx, parent.Scope, target.InstallationID)
	if err != nil {
		return agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetResolve, agentcoordination.ErrDenied)
	}
	want, _ := json.Marshal(target)
	got, _ := json.Marshal(routeTarget(parent.Scope, current))
	if string(want) != string(got) {
		return agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetFacts, nil)
	}
	_, err = a.authorizeDelegatedTargetTx(ctx, tx, parent.Scope, target)
	if err != nil {
		if _, _, classified := agentcoordination.RouteErrorClassification(err); classified {
			return err
		}
		return agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetAuthority, err)
	}
	return err
}
