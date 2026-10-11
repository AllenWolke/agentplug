package main

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// openIndexTaskModels issues a fresh lease-bound context from the actual
// persisted execution command. It never accepts job input as signing claims
// and never stores workload secrets or JWTs in the command/checkpoint tables.
func (p knowledgePersistence) openIndexTaskModels(ctx context.Context, run platformruntime.Run, scope knowledge.ProjectionScope, signer execution.MachineRunContextSigner, module *capability.Module, credential capability.TaskWorkloadCredential) (capability.TaskEmbeddingSession, error) {
	empty := capability.TaskEmbeddingSession{}
	if signer == nil || module == nil || p.db == nil || p.execution == nil {
		return empty, knowledge.ErrInvalidProjection
	}
	current, err := p.execution.GetContext(ctx, run.ID)
	if err != nil {
		return empty, err
	}
	if current.Scope != run.Scope || current.Status != platformruntime.StatusRunning || current.Revision != run.Revision || current.LeaseToken != run.LeaseToken {
		return empty, platformruntime.ErrLeaseConflict
	}
	var request contract.ExecuteRequest
	if json.Unmarshal(current.RequestJSON, &request) != nil {
		return empty, knowledge.ErrInvalidProjection
	}
	request.ContextToken = ""
	if request.Operation != "invoke" && request.Operation != "run" && request.Operation != "resume" {
		return empty, knowledge.ErrInvalidProjection
	}
	if request.Operation == "resume" {
		return empty, knowledge.ErrInvalidProjection
	} // indexing has no interactive resume command
	digest, err := contract.CanonicalExecuteBodyHash(request)
	if err != nil {
		return empty, err
	}
	policy, ok := request.Input["policy_snapshot"].(map[string]any)
	if !ok {
		return empty, knowledge.ErrInvalidProjection
	}
	policyHash, _ := policy["content_hash"].(string)
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := p.authorize(ctx, tx, run.Scope, scope); err != nil {
		return empty, err
	}
	if err := p.execution.CheckTaskLeaseTx(ctx, tx, run.Scope, run.LeaseToken, run.Revision); err != nil {
		return empty, err
	}
	token, err := signer.Sign(sharedkernel.BindExecutionLease(ctx, run.Revision, run.LeaseToken), run.Scope, request)
	if err != nil {
		return empty, err
	}
	command := platformruntime.DispatchCommand{RunID: run.ID, Revision: run.Revision, Operation: request.Operation, BodyHash: digest, PolicyHash: policyHash}
	if err := p.execution.RecordInternalTaskCommandTx(ctx, tx, run.Scope, run.LeaseToken, run.Revision, command); err != nil {
		return empty, err
	}
	if err := p.authorize(ctx, tx, run.Scope, scope); err != nil {
		return empty, err
	}
	if err := p.execution.CheckTaskLeaseTx(ctx, tx, run.Scope, run.LeaseToken, run.Revision); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	// Admission reads the committed command and independently rechecks live
	// Run/IAM/workload/model facts; no uncommitted command is trusted.
	r, err := module.BuildTaskEmbeddingRequest(ctx, request, token, credential)
	if err != nil {
		return empty, err
	}
	return module.OpenTaskEmbeddingSession(ctx, r, run.Scope)
}
