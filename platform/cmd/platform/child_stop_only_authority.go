package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/identity"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ParentForChildStop verifies only the identity and live generation needed to
// stop a previously admitted edge. It deliberately does not evaluate current
// run/agent.delegate permissions or current authorization epochs.
func (a agentRouteAuthority) ParentForChildStop(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, identityProof agentcoordination.ChildStopIdentity) (agentcoordination.ParentFacts, error) {
	deny := agentcoordination.ParentFacts{}
	if tx == nil || a.identity == nil || a.runs == nil || a.routes == nil || a.resources.identity == nil || a.resources.execution == nil || scope.ValidateTrusted() != nil ||
		identityProof.Lease.Revision == 0 || identityProof.PolicyHash == "" || identityProof.MachinePrincipalID == "" {
		return deny, agentcoordination.ErrDenied
	}
	if err := a.identity.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return deny, agentcoordination.ErrDenied
	}
	if err := lockBudgetAncestors(ctx, tx, a.runs, scope); err != nil {
		return deny, agentcoordination.ErrDenied
	}
	if err := a.runs.CheckCapabilityLeaseTx(ctx, tx, scope, identityProof.Lease); err != nil {
		return deny, agentcoordination.ErrDenied
	}
	run, err := a.runs.BudgetRunTx(ctx, tx, scope.RunID)
	if err != nil || run.Scope != scope || run.Status != platformruntime.StatusRunning || !run.HasLease {
		return deny, agentcoordination.ErrDenied
	}
	command, err := stopOnlyRunCommand(run.RequestJSON, scope)
	if err != nil {
		return deny, agentcoordination.ErrDenied
	}
	if identityProof.PolicyHash != strings.ToLower(identityProof.PolicyHash) || !validStopHash(identityProof.PolicyHash) {
		return deny, agentcoordination.ErrDenied
	}
	actor, err := a.identity.PermissionSnapshot(ctx, identity.PrincipalType(scope.PrincipalType), scope.PrincipalID)
	if err != nil || actor.Mode != "v2" || !actor.Principal.IsActive || actor.Principal.ID != scope.PrincipalID || string(actor.Principal.Type) != scope.PrincipalType || actor.Principal.TenantID != scope.TenantID {
		return deny, agentcoordination.ErrDenied
	}
	clientID, secret, peer, err := capability.AgentCoordinationStopWorkloadProof(ctx, scope)
	if err != nil || clientID != identityProof.MachinePrincipalID || a.resources.AuthenticateWorkload(ctx, scope, clientID, secret, peer) != nil {
		return deny, agentcoordination.ErrDenied
	}
	binding, err := a.workloadMachine(ctx, scope)
	if err != nil || binding.PrincipalID != identityProof.MachinePrincipalID {
		return deny, agentcoordination.ErrDenied
	}
	if err := a.validateStopOnlyPersistedLineageTx(ctx, tx, scope, int(command.Scope.DelegationDepth), identityProof.MachinePrincipalID); err != nil {
		return deny, agentcoordination.ErrDenied
	}
	return agentcoordination.ParentFacts{Scope: scope, PolicyHash: identityProof.PolicyHash, Depth: int(command.Scope.DelegationDepth), Active: true}, nil
}

func stopOnlyRunCommand(raw []byte, scope sharedkernel.Scope) (contract.ExecuteRequest, error) {
	var command contract.ExecuteRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF || command.ProtocolVersion != contract.ProtocolVersion || command.Operation != "run" {
		return contract.ExecuteRequest{}, errors.New("persisted parent command is invalid")
	}
	depth := command.Scope.DelegationDepth
	want := contract.ScopeKey{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentInstanceID: scope.AgentInstanceID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, PrincipalType: scope.PrincipalType, PrincipalID: scope.PrincipalID, SessionID: scope.SessionID, RunID: scope.RunID, AuthorizationEpoch: scope.AuthorizationEpoch, TraceID: scope.TraceID, ParentRunID: scope.ParentRunID, DelegationDepth: depth, InstallationID: scope.InstallationID}
	if command.Scope != want || depth > 4 || (depth == 0) != (scope.ParentRunID == "") || command.Scope.Validate() != nil {
		return contract.ExecuteRequest{}, errors.New("persisted parent scope mismatch")
	}
	return command, nil
}

func (a agentRouteAuthority) validateStopOnlyPersistedLineageTx(ctx context.Context, tx *sql.Tx, parent sharedkernel.Scope, depth int, machineID string) error {
	if depth == 0 {
		stamp, err := a.routes.RootMachineAuthorityTx(ctx, tx, parent.RunID)
		if err != nil || stamp.RootRunID != parent.RunID || stamp.RootInstallationID != parent.InstallationID || stamp.RootPrincipalType != parent.PrincipalType || stamp.RootPrincipalID != parent.PrincipalID || stamp.RootAuthorizationEpoch != parent.AuthorizationEpoch || stamp.MachinePrincipalID != machineID {
			return agentcoordination.ErrDenied
		}
		return nil
	}
	if depth < 1 || depth > 4 || parent.ParentRunID == "" {
		return agentcoordination.ErrDenied
	}
	ancestor, err := a.runs.BudgetRunTx(ctx, tx, parent.ParentRunID)
	if err != nil || ancestor.Scope.ValidateTrusted() != nil || ancestor.Scope.RunID != parent.ParentRunID || ancestor.Scope.PrincipalType != parent.PrincipalType || ancestor.Scope.PrincipalID != parent.PrincipalID || ancestor.Scope.SessionID != parent.SessionID {
		return agentcoordination.ErrDenied
	}
	proof, err := a.routes.DelegationAuthorityProofForDisclosureTx(ctx, tx, ancestor.Scope, parent, depth)
	if err != nil || !agentcoordination.ValidDelegationAuthorityProof(proof) || len(proof.Edges) != depth {
		return agentcoordination.ErrDenied
	}
	last := proof.Edges[len(proof.Edges)-1]
	if last.ParentRunID != ancestor.Scope.RunID || last.ChildRunID != parent.RunID || last.ParentInstallationID != ancestor.Scope.InstallationID || last.TargetInstallationID != parent.InstallationID || last.TargetAgentID != parent.AgentID || last.TargetVersionID != parent.AgentVersionID || last.TargetMachinePrincipalID != machineID {
		return agentcoordination.ErrDenied
	}
	return a.validateStopRootProofTx(ctx, tx, proof)
}

// CancelChildForStop is the execution boundary for stop-only cancellation.
// It revalidates the same persisted lineage and exact parent lease in the
// cancellation transaction, then writes only the child stop intent/CAS.
func (a childExecutionAdmitter) CancelChildForStop(ctx context.Context, tx *sql.Tx, request agentcoordination.ChildExecutionRead, identityProof agentcoordination.ChildStopIdentity, expected uint64) (agentcoordination.ChildExecutionResult, error) {
	empty := agentcoordination.ChildExecutionResult{}
	parent := request.Parent.Scope
	if tx == nil || a.route.runs == nil || a.route.routes == nil || identityProof.MachinePrincipalID == "" || identityProof.PolicyHash != request.Parent.PolicyHash {
		return empty, agentcoordination.ErrDenied
	}
	if err := a.route.runs.CheckCapabilityLeaseTx(ctx, tx, parent, identityProof.Lease); err != nil {
		return empty, agentcoordination.ErrDenied
	}
	if err := a.route.validateStopOnlyPersistedLineageTx(ctx, tx, parent, request.Depth-1, identityProof.MachinePrincipalID); err != nil {
		return empty, agentcoordination.ErrDenied
	}
	facts, err := a.route.runs.BudgetRunTx(ctx, tx, request.RunID)
	if err != nil || facts.Scope.AgentID != request.Target.AgentID || facts.Scope.InstallationID != request.Target.InstallationID || facts.Scope.AgentVersionID != request.Target.VersionID || a.route.routes.CheckRecordedChildEdgeTx(ctx, tx, parent, facts.Scope, request.Depth) != nil {
		return empty, agentcoordination.ErrDenied
	}
	childProof, err := a.route.routes.DelegationAuthorityProofForDisclosureTx(ctx, tx, parent, facts.Scope, request.Depth)
	if err != nil || !agentcoordination.ValidDelegationAuthorityProof(childProof) || !a.route.childStopProofMatchesParentTx(ctx, tx, parent, facts.Scope, request.Depth, request.Target, identityProof.MachinePrincipalID, childProof) {
		return empty, agentcoordination.ErrDenied
	}
	cancelled, err := a.route.runs.BeginCoordinatedChildCancellationTx(ctx, tx, parent, identityProof.Lease, facts.Scope, request.Depth, expected)
	if errors.Is(err, platformruntime.ErrRevisionConflict) {
		status := string(cancelled.Status)
		if cancelled.Revision > 0 && (status == "accepted" || status == "running" || status == "waiting") {
			return empty, &agentcoordination.ChildStopRevisionConflict{Status: status, ExecutionRevision: cancelled.Revision}
		}
		return empty, agentcoordination.ErrConflict
	}
	if errors.Is(err, platformruntime.ErrInvalidTransition) {
		return empty, agentcoordination.ErrConflict
	}
	if err != nil {
		return empty, err
	}
	status := string(cancelled.Status)
	if cancelled.Status == platformruntime.StatusSucceeded {
		status = "completed"
	}
	return agentcoordination.ChildExecutionResult{Scope: cancelled.Scope, Status: status, Revision: cancelled.Revision}, nil
}

func (a agentRouteAuthority) childStopProofMatchesParentTx(ctx context.Context, tx *sql.Tx, parent, child sharedkernel.Scope, depth int, target agentcoordination.Target, machineID string, childProof agentcoordination.DelegationAuthorityProof) bool {
	if len(childProof.Edges) != depth || childProof.RootRunID == "" {
		return false
	}
	last := childProof.Edges[len(childProof.Edges)-1]
	if last.ParentRunID != parent.RunID || last.ChildRunID != child.RunID || last.ParentInstallationID != parent.InstallationID || last.ParentMachinePrincipalID != machineID || last.TargetInstallationID != target.InstallationID || last.TargetAgentID != target.AgentID || last.TargetVersionID != target.VersionID || last.TargetManifestHash != target.ManifestHash {
		return false
	}
	if depth == 1 {
		stamp, err := a.routes.RootMachineAuthorityTx(ctx, tx, parent.RunID)
		return err == nil && stopProofMatchesRootStamp(childProof, stamp) && stamp.RootRunID == parent.RunID && stamp.RootInstallationID == parent.InstallationID && stamp.RootPrincipalType == parent.PrincipalType && stamp.RootPrincipalID == parent.PrincipalID && stamp.RootAuthorizationEpoch == parent.AuthorizationEpoch && stamp.MachinePrincipalID == machineID
	}
	ancestor, err := a.runs.BudgetRunTx(ctx, tx, parent.ParentRunID)
	if err != nil {
		return false
	}
	incoming, err := a.routes.DelegationAuthorityProofForDisclosureTx(ctx, tx, ancestor.Scope, parent, depth-1)
	if err != nil || !agentcoordination.ValidDelegationAuthorityProof(incoming) || len(incoming.Edges)+1 != len(childProof.Edges) || !sameStopProofRoot(incoming, childProof) {
		return false
	}
	for index, edge := range incoming.Edges {
		if edge != childProof.Edges[index] {
			return false
		}
	}
	return true
}

func (a agentRouteAuthority) validateStopRootProofTx(ctx context.Context, tx *sql.Tx, proof agentcoordination.DelegationAuthorityProof) error {
	stamp, err := a.routes.RootMachineAuthorityTx(ctx, tx, proof.RootRunID)
	if err != nil || !stopProofMatchesRootStamp(proof, stamp) {
		return agentcoordination.ErrDenied
	}
	root, err := a.runs.BudgetRunTx(ctx, tx, proof.RootRunID)
	if err != nil || root.Scope.ParentRunID != "" || root.Scope.InstallationID != proof.RootInstallationID || root.Scope.PrincipalType != proof.RootPrincipalType || root.Scope.PrincipalID != proof.RootPrincipalID || root.Scope.AuthorizationEpoch != proof.RootAuthorizationEpoch {
		return agentcoordination.ErrDenied
	}
	return nil
}

func stopProofMatchesRootStamp(proof agentcoordination.DelegationAuthorityProof, stamp agentcoordination.RootMachineAuthorityStamp) bool {
	return proof.RootRunID == stamp.RootRunID && proof.RootInstallationID == stamp.RootInstallationID && proof.RootPrincipalType == stamp.RootPrincipalType && proof.RootPrincipalID == stamp.RootPrincipalID && proof.RootAuthorizationEpoch == stamp.RootAuthorizationEpoch && proof.RootMachinePrincipalID == stamp.MachinePrincipalID && proof.RootMachineRunEpoch == stamp.MachineRunEpoch
}

func sameStopProofRoot(left, right agentcoordination.DelegationAuthorityProof) bool {
	return left.Version == right.Version && left.RootRunID == right.RootRunID && left.RootInstallationID == right.RootInstallationID && left.RootPrincipalType == right.RootPrincipalType && left.RootPrincipalID == right.RootPrincipalID && left.RootAuthorizationEpoch == right.RootAuthorizationEpoch && left.RootMachinePrincipalID == right.RootMachinePrincipalID && left.RootMachineRunEpoch == right.RootMachineRunEpoch
}

func validStopHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var _ agentcoordination.SQLChildStopAuthority = agentRouteAuthority{}
var _ agentcoordination.ChildExecutionStopOnlyCanceller = childExecutionAdmitter{}
