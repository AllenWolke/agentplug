package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// epochMemo remembers authorization epochs already fenced in this context.
// The first read holds the source share until the caller commits; repeating
// that full snapshot is what made model admission consume its whole deadline.
type epochMemoKey struct{}

type epochMemo struct {
	tx   *sql.Tx
	mu   sync.Mutex
	hits map[string]uint64
}

func withEpochMemo(ctx context.Context, tx *sql.Tx) context.Context {
	if ctx == nil || tx == nil {
		return ctx
	}
	if memo, ok := ctx.Value(epochMemoKey{}).(*epochMemo); ok && memo.tx == tx {
		return ctx
	}
	return context.WithValue(ctx, epochMemoKey{}, &epochMemo{tx: tx, hits: map[string]uint64{}})
}

func epochMemoFor(ctx context.Context, tx *sql.Tx) *epochMemo {
	if ctx == nil || tx == nil {
		return nil
	}
	memo, _ := ctx.Value(epochMemoKey{}).(*epochMemo)
	if memo == nil || memo.tx != tx {
		return nil
	}
	return memo
}

func epochMemoID(scope sharedkernel.Scope, action string) string {
	return strings.Join([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, action}, "\x00")
}

func delegationTargetScope(parent sharedkernel.Scope, target agentcoordination.Target, principalType, principalID string) sharedkernel.Scope {
	return delegationTargetScopeWithEpoch(parent, target, principalType, principalID, parent.AuthorizationEpoch)
}

func delegationTargetScopeWithEpoch(parent sharedkernel.Scope, target agentcoordination.Target, principalType, principalID string, authorizationEpoch uint64) sharedkernel.Scope {
	return sharedkernel.Scope{
		TenantID: target.TenantID, DepartmentID: target.DepartmentID, ApplicationID: target.ApplicationID,
		AgentID: target.AgentID, AgentInstanceID: target.InstallationID, InstallationID: target.InstallationID,
		AgentVersionID: target.VersionID, PrincipalType: principalType, PrincipalID: principalID,
		SessionID: parent.SessionID, RunID: parent.RunID, TraceID: parent.TraceID, AuthorizationEpoch: authorizationEpoch,
	}
}

func workloadCredentialMatches(binding identity.WorkloadBinding, credential identity.MachineCredential) bool {
	return binding.PrincipalID != "" && binding.TenantID == credential.TenantID && binding.PrincipalID == credential.PrincipalID &&
		credential.Status == "active" && credential.Revision > 0
}

func (a agentRouteAuthority) currentPrincipalPermissionTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action string) (uint64, error) {
	if a.identity == nil || tx == nil || scope.Validate() != nil || action == "" {
		return 0, agentcoordination.ErrDenied
	}
	ctx = withEpochMemo(ctx, tx)
	memoID := epochMemoID(scope, action)
	if memo := epochMemoFor(ctx, tx); memo != nil {
		memo.mu.Lock()
		epoch, found := memo.hits[memoID]
		memo.mu.Unlock()
		if found {
			return epoch, nil
		}
	}
	snapshot, err := a.identity.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if ancestryLockWait(err) {
		return 0, err
	}
	if err != nil || snapshot.Mode != "v2" || snapshot.Principal.ID != scope.PrincipalID || string(snapshot.Principal.Type) != scope.PrincipalType {
		return 0, agentcoordination.ErrDenied
	}
	decision, err := identity.EvaluatePermission(snapshot, identity.PermissionQuery{
		Action:       action,
		Scope:        identity.ManagementScope{Type: "agent_installation", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, ResourceID: scope.InstallationID},
		ResourceType: "agent_installation", ResourceID: scope.InstallationID, Now: time.Now().UTC(),
	})
	if ancestryLockWait(err) {
		return 0, err
	}
	if err != nil || !decision.Allowed {
		return 0, agentcoordination.ErrDenied
	}
	epoch, err := a.identity.CurrentAuthorizationEpochTx(ctx, tx, scope, action)
	if ancestryLockWait(err) {
		return 0, err
	}
	if err != nil || epoch == 0 {
		return 0, agentcoordination.ErrDenied
	}
	if memo := epochMemoFor(ctx, tx); memo != nil {
		memo.mu.Lock()
		memo.hits[memoID] = epoch
		memo.mu.Unlock()
	}
	return epoch, nil
}

func (a agentRouteAuthority) workloadMachine(ctx context.Context, scope sharedkernel.Scope) (identity.WorkloadBinding, error) {
	resolver, ok := any(a.identity).(identity.WorkloadIdentityResolver)
	if !ok || a.identity == nil {
		return identity.WorkloadBinding{}, agentcoordination.ErrDenied
	}
	binding, err := resolver.ResolveWorkloadIdentity(ctx, scope)
	if err != nil || binding.Status != "active" || binding.Revision == 0 || binding.AgentID != scope.AgentID || binding.InstallationID != scope.InstallationID || binding.AgentVersionID != scope.AgentVersionID || binding.TenantID != scope.TenantID || binding.DepartmentID != scope.DepartmentID || binding.ApplicationID != scope.ApplicationID || binding.PrincipalID == "" {
		return identity.WorkloadBinding{}, agentcoordination.ErrDenied
	}
	credential, err := a.identity.GetMachineCredential(ctx, scope.TenantID, binding.PrincipalID)
	if err != nil || !workloadCredentialMatches(binding, credential) {
		return identity.WorkloadBinding{}, agentcoordination.ErrDenied
	}
	return binding, nil
}

func (a agentRouteAuthority) PinRootMachineAuthority(ctx context.Context, scope sharedkernel.Scope) error {
	if a.identity == nil || a.runs == nil || a.routes == nil || scope.ValidateTrusted() != nil || scope.ParentRunID != "" {
		return agentcoordination.ErrDenied
	}
	tx, err := a.runs.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx = withEpochMemo(ctx, tx)
	if err = a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	run, err := a.runs.BudgetRunTx(ctx, tx, scope.RunID)
	if err != nil || run.Scope != scope {
		return agentcoordination.ErrDenied
	}
	actorEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, scope, "run")
	if err != nil || actorEpoch != scope.AuthorizationEpoch {
		return agentcoordination.ErrDenied
	}
	machine, err := a.workloadMachine(ctx, scope)
	if err != nil {
		return err
	}
	machineScope := scope
	machineScope.PrincipalType, machineScope.PrincipalID = string(identity.PrincipalServicePrincipal), machine.PrincipalID
	machineEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, machineScope, "run")
	if err != nil {
		return err
	}
	stamp := agentcoordination.RootMachineAuthorityStamp{RootRunID: scope.RunID, RootInstallationID: scope.InstallationID, RootPrincipalType: scope.PrincipalType, RootPrincipalID: scope.PrincipalID, RootAuthorizationEpoch: actorEpoch, MachinePrincipalID: machine.PrincipalID, MachineRunEpoch: machineEpoch}
	if err = a.routes.PinRootMachineAuthorityTx(ctx, tx, stamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (a agentRouteAuthority) authorizeDelegatedTargetTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, target agentcoordination.Target) (agentcoordination.DelegationAuthorityProofEdge, error) {
	var edge agentcoordination.DelegationAuthorityProofEdge
	if tx == nil || target.TenantID != parent.TenantID || target.DepartmentID != parent.DepartmentID || target.ApplicationID != parent.ApplicationID {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetFacts, nil)
	}
	ctx = withEpochMemo(ctx, tx)
	parentMachine, err := a.workloadMachine(ctx, parent)
	if err != nil {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonParentMachineBinding, err)
	}
	parentActorTarget := delegationTargetScope(parent, target, parent.PrincipalType, parent.PrincipalID)
	parentMachineTarget := delegationTargetScope(parent, target, string(identity.PrincipalServicePrincipal), parentMachine.PrincipalID)
	callerEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, parentActorTarget, "agent.delegate")
	if err != nil {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonCallerDelegate, err)
	}
	parentMachineEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, parentMachineTarget, "agent.delegate")
	if err != nil {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonParentMachineDelegate, err)
	}
	// ResolveWorkloadIdentity requires a trusted target scope. Bind it to the
	// caller's independently checked delegate epoch; the parent's root epoch
	// belongs to a different installation and must not be copied here.
	targetScope := delegationTargetScopeWithEpoch(parent, target, parent.PrincipalType, parent.PrincipalID, callerEpoch)
	targetMachine, err := a.workloadMachine(ctx, targetScope)
	if err != nil {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetMachineBinding, err)
	}
	targetMachineScope := delegationTargetScope(parent, target, string(identity.PrincipalServicePrincipal), targetMachine.PrincipalID)
	targetMachineEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, targetMachineScope, "run")
	if err != nil {
		return edge, agentcoordination.ClassifyRouteError(agentcoordination.RouteDenialTargetAuthorization, agentcoordination.RouteReasonTargetMachineRun, err)
	}
	edge = agentcoordination.DelegationAuthorityProofEdge{
		ParentRunID: parent.RunID, ChildRunID: "", ParentInstallationID: parent.InstallationID,
		ParentMachinePrincipalID: parentMachine.PrincipalID, TargetInstallationID: target.InstallationID,
		TargetAgentID: target.AgentID, TargetVersionID: target.VersionID, TargetManifestHash: target.ManifestHash,
		CallerDelegateEpoch: callerEpoch, ParentMachineDelegateEpoch: parentMachineEpoch,
		TargetMachinePrincipalID: targetMachine.PrincipalID, TargetMachineRunEpoch: targetMachineEpoch,
	}
	return edge, nil
}

func (a agentRouteAuthority) newDelegationAuthorityProofTx(ctx context.Context, tx *sql.Tx, parent agentcoordination.ParentFacts, target agentcoordination.Target, childRunID string) (string, error) {
	if tx == nil || a.runs == nil || a.routes == nil || childRunID == "" || parent.Depth < 0 || parent.Depth > 3 {
		return "", agentcoordination.ErrDenied
	}
	ctx = withEpochMemo(ctx, tx)
	var proof agentcoordination.DelegationAuthorityProof
	if parent.Depth == 0 {
		if parent.Scope.ParentRunID != "" {
			return "", agentcoordination.ErrDenied
		}
		root, err := a.runs.BudgetRunTx(ctx, tx, parent.Scope.RunID)
		if err != nil || root.Scope != parent.Scope || root.Scope.AuthorizationEpoch == 0 {
			return "", agentcoordination.ErrDenied
		}
		actorRunEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, root.Scope, "run")
		if err != nil || actorRunEpoch != root.Scope.AuthorizationEpoch {
			return "", agentcoordination.ErrDenied
		}
		stamp, err := a.routes.RootMachineAuthorityTx(ctx, tx, root.Scope.RunID)
		if err != nil || stamp.RootInstallationID != root.Scope.InstallationID || stamp.RootPrincipalType != root.Scope.PrincipalType || stamp.RootPrincipalID != root.Scope.PrincipalID || stamp.RootAuthorizationEpoch != root.Scope.AuthorizationEpoch {
			return "", agentcoordination.ErrDenied
		}
		machine, err := a.workloadMachine(ctx, root.Scope)
		if err != nil {
			return "", err
		}
		if machine.PrincipalID != stamp.MachinePrincipalID {
			return "", agentcoordination.ErrDenied
		}
		machineScope := root.Scope
		machineScope.PrincipalType, machineScope.PrincipalID = string(identity.PrincipalServicePrincipal), machine.PrincipalID
		machineEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, machineScope, "run")
		if err != nil || machineEpoch != stamp.MachineRunEpoch {
			return "", agentcoordination.ErrDenied
		}
		proof = agentcoordination.DelegationAuthorityProof{Version: "agent-delegation-authority/v1", RootRunID: root.Scope.RunID, RootInstallationID: root.Scope.InstallationID, RootPrincipalType: root.Scope.PrincipalType, RootPrincipalID: root.Scope.PrincipalID, RootAuthorizationEpoch: root.Scope.AuthorizationEpoch, RootMachinePrincipalID: machine.PrincipalID, RootMachineRunEpoch: machineEpoch}
	} else {
		parentFacts, err := a.runs.BudgetRunTx(ctx, tx, parent.Scope.RunID)
		if err != nil || parentFacts.Scope != parent.Scope || parent.Scope.ParentRunID == "" {
			return "", agentcoordination.ErrDenied
		}
		ancestor, err := a.runs.BudgetRunTx(ctx, tx, parent.Scope.ParentRunID)
		if err != nil {
			return "", agentcoordination.ErrDenied
		}
		proof, err = a.routes.DelegationAuthorityProofTx(ctx, tx, ancestor.Scope, parent.Scope, parent.Depth)
		if err != nil || a.checkDelegationAuthorityProofTx(ctx, tx, proof) != nil {
			return "", agentcoordination.ErrDenied
		}
	}
	edge, err := a.authorizeDelegatedTargetTx(ctx, tx, parent.Scope, target)
	if err != nil {
		return "", err
	}
	edge.ChildRunID = childRunID
	proof.Edges = append(proof.Edges, edge)
	if !agentcoordination.ValidDelegationAuthorityProof(proof) {
		return "", agentcoordination.ErrDenied
	}
	raw, err := json.Marshal(proof)
	if err != nil || len(raw) > 32768 {
		return "", agentcoordination.ErrDenied
	}
	return string(raw), nil
}

func (a agentRouteAuthority) checkDelegationAuthorityProofTx(ctx context.Context, tx *sql.Tx, proof agentcoordination.DelegationAuthorityProof) error {
	return a.checkDelegationAuthorityProof(ctx, tx, proof, false, "")
}

func (a agentRouteAuthority) checkDelegationAuthorityProofForDisclosureTx(ctx context.Context, tx *sql.Tx, proof agentcoordination.DelegationAuthorityProof) error {
	return a.checkDelegationAuthorityProof(ctx, tx, proof, true, "")
}

// checkDelegationAuthorityProofForLiveActorTx keeps every edge, epoch and
// policy comparison. unlockedActor is the run whose FOR UPDATE fence is already
// owned by the live dispatcher or capability transaction; sharing it again from
// this transaction deadlocks the child lifecycle reconciler.
func (a agentRouteAuthority) checkDelegationAuthorityProofForLiveActorTx(ctx context.Context, tx *sql.Tx, proof agentcoordination.DelegationAuthorityProof, unlockedActor string) error {
	if unlockedActor == "" {
		return agentcoordination.ErrDenied
	}
	return a.checkDelegationAuthorityProof(ctx, tx, proof, false, unlockedActor)
}

func (a agentRouteAuthority) checkDelegationAuthorityProof(ctx context.Context, tx *sql.Tx, proof agentcoordination.DelegationAuthorityProof, recorded bool, unlockedActor string) error {
	if tx == nil || a.runs == nil || a.routes == nil || !agentcoordination.ValidDelegationAuthorityProof(proof) {
		return agentcoordination.ErrDenied
	}
	ctx = withEpochMemo(ctx, tx)
	readRun := func(id string) (execution.BudgetRunFacts, error) {
		if unlockedActor != "" && id == unlockedActor {
			return a.runs.BudgetRunReadTx(ctx, tx, id)
		}
		return a.runs.BudgetRunTx(ctx, tx, id)
	}
	root, err := readRun(proof.RootRunID)
	if err = ancestryDeny(err); err != nil {
		return err
	}
	if root.Scope.ParentRunID != "" || root.Scope.InstallationID != proof.RootInstallationID || root.Scope.PrincipalType != proof.RootPrincipalType || root.Scope.PrincipalID != proof.RootPrincipalID || root.Scope.AuthorizationEpoch != proof.RootAuthorizationEpoch {
		return agentcoordination.ErrDenied
	}
	rootActorEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, root.Scope, "run")
	if err = ancestryDeny(err); err != nil {
		return err
	}
	if rootActorEpoch != proof.RootAuthorizationEpoch {
		return agentcoordination.ErrDenied
	}
	rootMachine := root.Scope
	rootMachine.PrincipalType, rootMachine.PrincipalID = string(identity.PrincipalServicePrincipal), proof.RootMachinePrincipalID
	stamp, err := a.routes.RootMachineAuthorityTx(ctx, tx, proof.RootRunID)
	if err = ancestryDeny(err); err != nil {
		return err
	}
	if stamp.RootInstallationID != proof.RootInstallationID || stamp.RootPrincipalType != proof.RootPrincipalType || stamp.RootPrincipalID != proof.RootPrincipalID || stamp.RootAuthorizationEpoch != proof.RootAuthorizationEpoch || stamp.MachinePrincipalID != proof.RootMachinePrincipalID || stamp.MachineRunEpoch != proof.RootMachineRunEpoch {
		return agentcoordination.ErrDenied
	}
	rootMachineEpoch, err := a.currentPrincipalPermissionTx(ctx, tx, rootMachine, "run")
	if err = ancestryDeny(err); err != nil {
		return err
	}
	if rootMachineEpoch != proof.RootMachineRunEpoch {
		return agentcoordination.ErrDenied
	}
	for index, edge := range proof.Edges {
		parent, err := readRun(edge.ParentRunID)
		if err = ancestryDeny(err); err != nil {
			return err
		}
		child, childErr := readRun(edge.ChildRunID)
		if childErr = ancestryDeny(childErr); childErr != nil {
			return childErr
		}
		var edgeErr error
		if recorded {
			edgeErr = a.routes.CheckRecordedChildEdgeTx(ctx, tx, parent.Scope, child.Scope, index+1)
		} else {
			edgeErr = a.routes.CheckChildEdgeTx(ctx, tx, parent.Scope, child.Scope, index+1)
		}
		if edgeErr = ancestryDeny(edgeErr); edgeErr != nil {
			return edgeErr
		}
		if child.Scope.ParentRunID != parent.Scope.RunID || child.Scope.InstallationID != edge.TargetInstallationID || child.Scope.AgentID != edge.TargetAgentID || child.Scope.AgentVersionID != edge.TargetVersionID {
			return agentcoordination.ErrDenied
		}
		var binding agentcoordination.ChildRoutingFacts
		if recorded {
			binding, err = a.routes.RecordedChildRoutingFactsTx(ctx, tx, parent.Scope, child.Scope, index+1)
		} else {
			binding, err = a.routes.ChildRoutingFactsTx(ctx, tx, parent.Scope, child.Scope, index+1)
		}
		if err = ancestryDeny(err); err != nil {
			return err
		}
		_, policy, policyErr := budgetRunPolicy(ctx, tx, parent)
		if policyErr = ancestryDeny(policyErr); policyErr != nil {
			return policyErr
		}
		if binding.Target.InstallationID != edge.TargetInstallationID || binding.Target.ManifestHash != edge.TargetManifestHash || binding.PolicyHash != policy.Hash || policy.Runtime.Delegation == nil || !delegatedContains(policy.Runtime.Delegation.AllowedAgentIDs, child.Scope.AgentID) || !delegatedContains(policy.Runtime.Delegation.TaskTypes, binding.TaskType) {
			return agentcoordination.ErrDenied
		}
		current, err := a.authorizeDelegatedTargetTx(ctx, tx, parent.Scope, binding.Target)
		if err = ancestryDeny(err); err != nil {
			return err
		}
		if current.ParentMachinePrincipalID != edge.ParentMachinePrincipalID || current.TargetMachinePrincipalID != edge.TargetMachinePrincipalID || current.CallerDelegateEpoch != edge.CallerDelegateEpoch || current.ParentMachineDelegateEpoch != edge.ParentMachineDelegateEpoch || current.TargetMachineRunEpoch != edge.TargetMachineRunEpoch {
			return agentcoordination.ErrDenied
		}
		if index == 0 && (parent.Scope.RunID != proof.RootRunID || edge.ParentMachinePrincipalID != proof.RootMachinePrincipalID) {
			return agentcoordination.ErrDenied
		}
	}
	return nil
}

func decodeDelegationAuthority(raw string) (agentcoordination.DelegationAuthorityProof, error) {
	var proof agentcoordination.DelegationAuthorityProof
	if len(raw) == 0 || len(raw) > 32768 || json.Unmarshal([]byte(raw), &proof) != nil || !agentcoordination.ValidDelegationAuthorityProof(proof) {
		return proof, agentcoordination.ErrDenied
	}
	return proof, nil
}
