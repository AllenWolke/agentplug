package main

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/agentcoordination"
	"github.com/lexagent/platform/internal/contract"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

func (a evaluationExecutionAuthority) AuthorizeSynchronousCreationTx(ctx context.Context, tx *sql.Tx, created platformruntime.CreateRequest) error {
	scope := created.Scope
	var request contract.ExecuteRequest
	if tx == nil || scope.ValidateTrusted() != nil || created.ID != scope.RunID || created.AgentVersionID != scope.AgentVersionID ||
		json.Unmarshal(created.RequestJSON, &request) != nil || request.Validate() != nil || request.Operation != "invoke" || request.ResumeInput != nil || request.Scope != evaluationContractScope(scope) || request.Scope.DelegationDepth != 0 || request.IdempotencyKey != created.IdempotencyKey {
		return agentcoordination.ErrDenied
	}
	fingerprint, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil || fingerprint != created.Fingerprint {
		return agentcoordination.ErrDenied
	}
	// This is a new request, never synthetic persisted Run/stop evidence.
	// Recheck real parent lease, IAM continuity and workload binding while the
	// same transaction will insert the child. Cancellation takes this head lock.
	parent, err := a.readBudgetParentTx(ctx, tx, scope, true, true)
	if err != nil {
		return err
	}
	snapshot := parent.snapshot
	index, valid := evaluationInvocationIndex(parent.resource.ID, parent.lease.IdempotencyKey, scope, request, len(snapshot.Dataset().Cases))
	if !valid || scope.TraceID != evaluationTraceID(parent.resource.ID, index) || !evaluationCaseRequestMatches(snapshot.Dataset().Cases[index], request.Input) {
		return agentcoordination.ErrDenied
	}
	target, err := a.catalog.ResolveEvaluationAgentTarget(ctx, scope, scope.AgentID, scope.AgentVersionID)
	if err != nil || target.InstallationID != scope.InstallationID || target.AgentID != scope.AgentID || target.AgentVersionID != scope.AgentVersionID || request.InputSchema != target.InputSchemaURI || !evaluationEndpointMatches(target.Endpoint, created.AgentEndpoint) || (snapshot.InstallationID() != "" && (snapshot.InstallationID() != scope.InstallationID || snapshot.InstallationRevision() != target.Revision)) {
		return agentcoordination.ErrDenied
	}
	policy, err := a.policies.Resolve(ctx, scope, scope.AgentVersionID)
	if err != nil {
		return agentcoordination.ErrDenied
	}
	input, err := policy.ExecutionInput()
	if err != nil || !evaluationInputHasPolicy(request.Input, input) {
		return agentcoordination.ErrDenied
	}
	return a.verifyJudgeSource(ctx, scope, request.Input)
}
