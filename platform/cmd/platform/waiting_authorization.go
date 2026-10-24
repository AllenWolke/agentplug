package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type waitingRunAuthorization struct {
	iam       *identity.SQLStore
	runs      *execution.SQLStore
	execution *execution.Module
	catalog   *catalog.Module
	policies  policyasset.Resolver
	resources capabilityExecutionAuthority
	routes    *agentcoordination.SQLRouteStore
	audit     audit.TxRecorder
}

func (a waitingRunAuthorization) configure() {
	if a.runs == nil {
		return
	}
	a.runs.SetWaitingAuthorizationPorts(execution.WaitingAuthorizationPorts{
		Fence: func(ctx context.Context, tx *sql.Tx) error {
			if a.iam == nil {
				return execution.ErrRunPermissionDenied
			}
			return a.iam.AcquirePermissionReadContinuity(ctx, tx)
		},
		Authorize:          a.authorize,
		RenewRootAuthority: a.renewRoot,
		Audit: func(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, receipt execution.WaitingAuthorizationReceipt) error {
			if a.audit == nil {
				return errors.New("authorization renewal audit unavailable")
			}
			return a.audit.RecordTx(tx, audit.Event{ID: "run-authority-" + receipt.RequestDigest, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID, AggregateType: "execution_run", AggregateID: scope.RunID, Action: "execution.authorization.renewed", Outcome: "success", Summary: "Waiting execution authorization renewed; original release, policy and budgets preserved", CreatedAt: receipt.OccurredAt})
		},
	})
}

func (a waitingRunAuthorization) authorize(ctx context.Context, tx *sql.Tx, actor execution.BrowserRunActor, facts execution.BudgetRunFacts) (uint64, error) {
	if a.iam == nil || a.execution == nil || a.catalog == nil || a.policies == nil || a.routes == nil {
		return 0, execution.ErrRunPermissionDenied
	}
	if err := a.iam.ValidateBrowserSessionTx(ctx, tx, actor.Scope, actor.AuthenticationSession, actor.AuthenticationRevision); err != nil {
		if errors.Is(err, identity.ErrRefreshSessionRejected) {
			return 0, execution.ErrBrowserSessionInvalid
		}
		return 0, err
	}
	if facts.Scope.ParentRunID != "" || facts.Scope.PrincipalID != actor.Scope.PrincipalID || facts.Scope.PrincipalType != "user" {
		return 0, execution.ErrRunPermissionDenied
	}
	var original contract.ExecuteRequest
	if json.Unmarshal(facts.RequestJSON, &original) != nil || original.Scope != budgetContractScope(facts.Scope) {
		return 0, execution.ErrRunPermissionDenied
	}
	if authorizeBusinessResource(ctx, a.iam, facts.Scope, actor.Scope.PrincipalID, "history.continue") != nil {
		return 0, execution.ErrRunPermissionDenied
	}
	metadata, err := a.execution.ResolveToolApprovalRun(ctx, actor.Scope, facts.Scope.RunID)
	if err != nil || metadata.Scope != facts.Scope {
		return 0, execution.ErrRunPermissionDenied
	}
	pinned := policyasset.SnapshotFromContext(metadata.PolicyIDs)
	policy, err := a.policies.Resolve(ctx, facts.Scope, facts.Scope.AgentVersionID)
	if err != nil || pinned.ValidateIDs() != nil || !policy.SameIDs(pinned) || !policy.SameRuleBinding(pinned) || policy.Hash != metadata.PolicyHash {
		return 0, execution.ErrRunPermissionDenied
	}
	if a.execution.ValidatePinnedRunTarget(ctx, facts.Scope) != nil {
		return 0, execution.ErrRunPermissionDenied
	}
	if a.resources.AuthorizeCapabilityResource(ctx, facts.Scope, capability.CapabilityResourceAccess{Action: "run", ResourceType: "agent_installation", ResourceID: facts.Scope.InstallationID}) != nil {
		return 0, execution.ErrRunPermissionDenied
	}
	epoch, err := a.iam.CurrentAuthorizationEpochTx(ctx, tx, facts.Scope, "run")
	if err != nil || epoch == 0 {
		return 0, execution.ErrRunPermissionDenied
	}
	return epoch, nil
}

func (a waitingRunAuthorization) renewRoot(ctx context.Context, tx *sql.Tx, old, next sharedkernel.Scope) error {
	if a.iam == nil || a.routes == nil {
		return execution.ErrRunPermissionDenied
	}
	route := agentRouteAuthority{identity: a.iam, runs: a.runs, routes: a.routes}
	machine, err := route.workloadMachine(ctx, next)
	if err != nil {
		return execution.ErrRunPermissionDenied
	}
	machineScope := next
	machineScope.PrincipalType, machineScope.PrincipalID = "service_principal", machine.PrincipalID
	epoch, err := route.currentPrincipalPermissionTx(ctx, tx, machineScope, "run")
	if err != nil {
		return execution.ErrRunPermissionDenied
	}
	stamp := agentcoordination.RootMachineAuthorityStamp{RootRunID: next.RunID, RootInstallationID: next.InstallationID, RootPrincipalType: next.PrincipalType, RootPrincipalID: next.PrincipalID, RootAuthorizationEpoch: next.AuthorizationEpoch, MachinePrincipalID: machine.PrincipalID, MachineRunEpoch: epoch}
	if a.routes.RenewUndelegatedRootAuthorityTx(ctx, tx, old.AuthorizationEpoch, stamp) != nil {
		return execution.ErrRunPermissionDenied
	}
	return nil
}
