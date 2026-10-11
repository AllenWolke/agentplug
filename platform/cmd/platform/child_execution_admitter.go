package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/policyasset"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type childExecutionAdmitter struct {
	route      agentRouteAuthority
	budget     *usagecost.SQLRunTreeBudgetStore
	quiescence func(context.Context, sharedkernel.Scope) error
}

func (a childExecutionAdmitter) CheckChildStopQuiescence(ctx context.Context, scope sharedkernel.Scope) error {
	if a.quiescence == nil {
		return agentcoordination.ErrUnavailable
	}
	return a.quiescence(ctx, scope)
}

func (a childExecutionAdmitter) AdmitChild(ctx context.Context, tx *sql.Tx, request agentcoordination.ChildExecutionAdmission) (agentcoordination.AdmittedChildExecution, error) {
	empty := agentcoordination.AdmittedChildExecution{}
	parent := request.Parent.Scope
	if tx == nil || a.budget == nil || a.route.identity == nil || a.route.runs == nil || a.route.catalog == nil || request.Input == nil || request.Depth != request.Parent.Depth+1 || request.Depth < 1 || request.Depth > 4 || a.route.identity.AcquirePermissionReadContinuity(ctx, tx) != nil {
		return empty, agentcoordination.ErrDenied
	}
	lease, parentPolicy, err := capability.AgentCoordinationAuthority(ctx, parent)
	if err != nil || parentPolicy.Hash != request.Parent.PolicyHash || a.route.runs.CheckCapabilityLeaseTx(ctx, tx, parent, lease) != nil || a.route.AuthorizeTarget(ctx, tx, request.Parent, request.Target) != nil {
		return empty, agentcoordination.ErrDenied
	}
	target, err := a.route.catalog.ResolveBusinessRouteTarget(ctx, parent, request.Target.InstallationID)
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	actual, _ := json.Marshal(routeTarget(parent, target))
	expected, _ := json.Marshal(request.Target)
	if string(actual) != string(expected) || target.Endpoint == "" || target.InputSchemaURI != request.InputSchema {
		return empty, agentcoordination.ErrDenied
	}
	child := sharedkernel.Scope{TenantID: parent.TenantID, DepartmentID: parent.DepartmentID, ApplicationID: parent.ApplicationID, AgentID: target.AgentID, AgentInstanceID: target.InstallationID, InstallationID: target.InstallationID, AgentVersionID: target.VersionID, PrincipalType: parent.PrincipalType, PrincipalID: parent.PrincipalID, SessionID: parent.SessionID, RunID: request.RunID, ParentRunID: parent.RunID, TraceID: parent.TraceID, AuthorizationEpoch: parent.AuthorizationEpoch}
	proofJSON, err := a.route.newDelegationAuthorityProofTx(ctx, tx, request.Parent, request.Target, child.RunID)
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	proof, err := decodeDelegationAuthority(proofJSON)
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	// A child inherits only the already-authorized root caller epoch. It does
	// not receive a user run grant on its target installation. The target
	// workload's own run permission and both explicit delegation grants are
	// carried by the private proof and rechecked live.
	child.AuthorizationEpoch = proof.RootAuthorizationEpoch
	policy, err := policyasset.NewSQLResolver(tx).Resolve(ctx, child, child.AgentVersionID)
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	policyInput, err := policy.ExecutionInput()
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	input := make(map[string]any, len(request.Input)+1)
	for key, value := range request.Input {
		input[key] = value
	}
	if _, forged := input["policy_snapshot"]; forged {
		return empty, agentcoordination.ErrDenied
	}
	input["policy_snapshot"] = policyInput
	// Pin root allowance with the parent admission, then reserve individual
	// provider costs when the child actually calls the common model gateway.
	if err = a.budget.CheckChildAdmissionTx(ctx, tx, parent); err != nil {
		return empty, err
	}
	command := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Scope: contract.ScopeKey{TenantID: child.TenantID, DepartmentID: child.DepartmentID, ApplicationID: child.ApplicationID, AgentID: child.AgentID, AgentInstanceID: child.AgentInstanceID, InstallationID: child.InstallationID, AgentVersionID: child.AgentVersionID, PrincipalType: child.PrincipalType, PrincipalID: child.PrincipalID, SessionID: child.SessionID, RunID: child.RunID, ParentRunID: child.ParentRunID, DelegationDepth: uint32(request.Depth), TraceID: child.TraceID, AuthorizationEpoch: child.AuthorizationEpoch}, Operation: "run", IdempotencyKey: request.IdempotencyKey, InputSchema: request.InputSchema, Input: input}
	if command.Scope.Validate() != nil {
		return empty, agentcoordination.ErrDenied
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil {
		return empty, err
	}
	body, err := json.Marshal(command)
	if err != nil || len(body) > 1<<20 {
		return empty, agentcoordination.ErrDenied
	}
	created, err := a.route.runs.CreateCoordinatedRunTx(ctx, tx, parent, lease, platformruntime.CreateRequest{ID: child.RunID, Scope: child, AgentVersionID: child.AgentVersionID, IdempotencyKey: request.IdempotencyKey, Fingerprint: fingerprint, RequestJSON: body, AgentEndpoint: target.Endpoint})
	if err != nil {
		return empty, err
	}
	if created.Run.ID != child.RunID || created.Run.Scope != child || created.Run.Status != platformruntime.StatusAccepted || created.Replayed {
		return empty, agentcoordination.ErrConflict
	}
	return agentcoordination.AdmittedChildExecution{Scope: child, RequestFingerprint: fingerprint, DelegationAuthorityJSON: proofJSON}, nil
}

var _ agentcoordination.ChildExecutionAdmitter = childExecutionAdmitter{}

// ReadChild returns only a current, bound execution result; it is not a history
// browsing API and never acknowledges, resumes or dispatches the child.
func (a childExecutionAdmitter) ReadChild(ctx context.Context, tx *sql.Tx, request agentcoordination.ChildExecutionRead) (agentcoordination.ChildExecutionResult, error) {
	empty := agentcoordination.ChildExecutionResult{}
	parent := request.Parent.Scope
	if tx == nil || a.route.runs == nil || a.route.identity == nil || a.route.routes == nil {
		return empty, agentcoordination.ErrUnavailable
	}
	if _, _, err := capability.AgentCoordinationAuthority(ctx, parent); err != nil {
		return empty, agentcoordination.ErrDenied
	}
	if a.route.AuthorizeTarget(ctx, tx, request.Parent, request.Target) != nil {
		return empty, agentcoordination.ErrDenied
	}
	read, err := a.route.runs.ChildResultTx(ctx, tx, parent, request.RunID)
	if err != nil {
		return empty, err
	}
	if read.Scope.InstallationID != request.Target.InstallationID || read.Scope.AgentID != request.Target.AgentID || read.Scope.AgentVersionID != request.Target.VersionID || a.route.routes.CheckRecordedChildEdgeTx(ctx, tx, parent, read.Scope, request.Depth) != nil {
		return empty, agentcoordination.ErrDenied
	}
	proof, proofErr := a.route.routes.DelegationAuthorityProofForDisclosureTx(ctx, tx, parent, read.Scope, request.Depth)
	if proofErr != nil || a.route.checkDelegationAuthorityProofForDisclosureTx(ctx, tx, proof) != nil {
		return empty, agentcoordination.ErrDenied
	}
	status := string(read.Status)
	result := agentcoordination.ChildExecutionResult{Scope: read.Scope, Status: status, Revision: read.Revision, RequestFingerprint: read.RequestFingerprint, OutputBytes: read.OutputBytes, OutputOmitted: read.OutputOmitted}
	if read.Status == platformruntime.StatusSucceeded {
		result.Status = "completed"
		if read.OutputAvailable {
			if len(read.OutputJSON) > 16384 {
				return empty, agentcoordination.ErrConflict
			}
			decoder := json.NewDecoder(bytes.NewReader(read.OutputJSON))
			decoder.UseNumber()
			if decoder.Decode(&result.Output) != nil || result.Output == nil || decoder.Decode(new(any)) != io.EOF {
				return empty, agentcoordination.ErrConflict
			}
			hash := sha256.Sum256(read.OutputJSON)
			result.OutputDigest = hex.EncodeToString(hash[:])
		} else if !read.OutputOmitted {
			result.Status = "uncertain"
		}
	} else if read.Status == platformruntime.StatusFailed || read.Status == platformruntime.StatusCancelled {
		proof, err := a.route.runs.ChildLifecycleTx(ctx, tx, parent, read.Scope)
		if err != nil {
			return empty, err
		}
		if !proof.TerminalVerified {
			result.Status = "uncertain"
		}
	}
	// Re-check target-machine authority immediately before handing metadata or
	// business output back to the coordinator's commit/final disclosure checks.
	proof, proofErr = a.route.routes.DelegationAuthorityProofForDisclosureTx(ctx, tx, parent, read.Scope, request.Depth)
	if proofErr != nil || a.route.checkDelegationAuthorityProofForDisclosureTx(ctx, tx, proof) != nil {
		return empty, agentcoordination.ErrDenied
	}
	return result, nil
}

var _ agentcoordination.ChildExecutionReader = childExecutionAdmitter{}

// CancelChild uses parent authority to stop an existing recorded child. It
// does not need to restore a revoked child-machine execution grant to stop it.
func (a childExecutionAdmitter) CancelChild(ctx context.Context, tx *sql.Tx, request agentcoordination.ChildExecutionRead, expected uint64) (agentcoordination.ChildExecutionResult, error) {
	empty := agentcoordination.ChildExecutionResult{}
	parent := request.Parent.Scope
	if tx == nil || a.route.runs == nil || a.route.routes == nil || a.route.identity == nil {
		return empty, agentcoordination.ErrUnavailable
	}
	lease, _, err := capability.AgentCoordinationAuthority(ctx, parent)
	if err != nil {
		return empty, agentcoordination.ErrDenied
	}
	facts, err := a.route.runs.BudgetRunTx(ctx, tx, request.RunID)
	if err != nil {
		return empty, err
	}
	if facts.Scope.AgentID != request.Target.AgentID || facts.Scope.InstallationID != request.Target.InstallationID || facts.Scope.AgentVersionID != request.Target.VersionID || a.route.routes.CheckRecordedChildEdgeTx(ctx, tx, parent, facts.Scope, request.Depth) != nil {
		return empty, agentcoordination.ErrDenied
	}
	cancelled, err := a.route.runs.BeginCoordinatedChildCancellationTx(ctx, tx, parent, lease, facts.Scope, request.Depth, expected)
	if errors.Is(err, platformruntime.ErrRevisionConflict) || errors.Is(err, platformruntime.ErrInvalidTransition) {
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

var _ agentcoordination.ChildExecutionCanceller = childExecutionAdmitter{}

func (a childExecutionAdmitter) ObserveChildLifecycle(ctx context.Context, tx *sql.Tx, request agentcoordination.ChildExecutionRead) (agentcoordination.ObservedChildLifecycle, error) {
	empty := agentcoordination.ObservedChildLifecycle{}
	if tx == nil || a.route.runs == nil || a.route.routes == nil {
		return empty, agentcoordination.ErrUnavailable
	}
	run, err := a.route.runs.BudgetRunReadTx(ctx, tx, request.RunID)
	if err != nil {
		return empty, err
	}
	if run.Scope.AgentID != request.Target.AgentID || run.Scope.InstallationID != request.Target.InstallationID || run.Scope.AgentVersionID != request.Target.VersionID || a.route.routes.CheckRecordedChildEdgeTx(ctx, tx, request.Parent.Scope, run.Scope, request.Depth) != nil {
		return empty, agentcoordination.ErrDenied
	}
	proof, err := a.route.runs.ChildLifecycleTx(ctx, tx, request.Parent.Scope, run.Scope)
	if err != nil {
		return empty, err
	}
	status := string(proof.Status)
	if proof.Status == platformruntime.StatusSucceeded {
		status = "completed"
	}
	return agentcoordination.ObservedChildLifecycle{Scope: proof.Scope, Status: status, Revision: proof.Revision, RequestFingerprint: proof.RequestFingerprint, TerminalVerified: proof.TerminalVerified}, nil
}

var _ agentcoordination.ChildExecutionLifecycleObserver = childExecutionAdmitter{}
