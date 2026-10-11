package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/telemetry"
)

func (c knowledgeControl) SubmitIndex(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, request knowledge.IndexTaskRequest) (knowledge.IndexTaskReceipt, error) {
	empty := knowledge.IndexTaskReceipt{}
	p := c.persistence
	if p.db == nil || p.iam == nil || p.execution == nil || p.audit == nil || c.targets == nil || c.policies == nil {
		return empty, knowledge.ErrCheckpointUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" {
		return empty, knowledge.ErrManagementDenied
	}
	if _, err := request.IndexConfig("published-target-required"); err != nil {
		return empty, err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	targets, err := c.targets.ListAvailableAgents(ctx, scope.TenantID, scope.DepartmentID, scope.ApplicationID)
	if err != nil {
		return empty, err
	}
	var target catalog.AvailableAgent
	for _, candidate := range targets {
		if candidate.InstallationID == request.InstallationID {
			if target.InstallationID != "" {
				return empty, knowledge.ErrInvalidProjection
			}
			target = candidate
		}
	}
	if target.InstallationID == "" || target.AgentID == "" || target.VersionID == "" {
		return empty, knowledge.ErrInvalidProjection
	}
	// Stable task/session/trace identities make retries independent of browser
	// request IDs. Changing parameters or the published policy changes the
	// fingerprint and conflicts with the existing idempotency key.
	owner := actor
	owner.AgentID = target.AgentID
	owner.AgentInstanceID = target.InstallationID
	owner.InstallationID = target.InstallationID
	owner.AgentVersionID = target.VersionID
	owner.AuthorizationEpoch, err = p.iam.CurrentAuthorizationEpoch(ctx, owner, "policy.manage")
	if err != nil {
		return empty, knowledgeControlError(err)
	}
	identity, _ := json.Marshal([]any{actor.TenantID, actor.DepartmentID, actor.ApplicationID, actor.PrincipalType, actor.PrincipalID, target.InstallationID, target.VersionID, owner.AuthorizationEpoch, request.IdempotencyKey})
	sum := sha256.Sum256(identity)
	id := hex.EncodeToString(sum[:])
	owner.RunID = "index-" + id
	owner.SessionID = "index-session-" + id
	owner.TraceID = id[:32]
	owner.ParentRunID = ""
	if owner.ValidateTrusted() != nil {
		return empty, knowledge.ErrInvalidProjection
	}
	snapshot, err := c.policies.Resolve(ctx, owner, target.VersionID)
	if err != nil {
		return empty, err
	}
	policy, err := snapshot.ExecutionInput()
	if err != nil {
		return empty, err
	}
	model, err := snapshot.Model.ForEmbedding()
	if err != nil {
		return empty, err
	}
	config, err := request.IndexConfig(model.ModelVersionID)
	if err != nil {
		return empty, err
	}
	command := contract.ExecuteRequest{ProtocolVersion: contract.ProtocolVersion, Operation: "invoke", InputSchema: execution.KnowledgeIndexInputSchema, IdempotencyKey: request.IdempotencyKey, Scope: contract.ScopeKey{TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, PrincipalID: owner.PrincipalID, PrincipalType: owner.PrincipalType, AgentID: owner.AgentID, AgentInstanceID: owner.AgentInstanceID, InstallationID: owner.InstallationID, AgentVersionID: owner.AgentVersionID, SessionID: owner.SessionID, RunID: owner.RunID, TraceID: owner.TraceID, AuthorizationEpoch: owner.AuthorizationEpoch}, Input: map[string]any{"knowledge_id": scope.KnowledgeID, "index_mode": request.Mode, "index_config": config, "policy_snapshot": policy}}
	digest, err := contract.CanonicalExecuteBodyHash(command)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return empty, err
	}
	tx, err = p.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	created, err := p.execution.CreateInternalTaskTx(ctx, tx, platformruntime.CreateRequest{ID: owner.RunID, Scope: owner, AgentVersionID: owner.AgentVersionID, IdempotencyKey: request.IdempotencyKey, Fingerprint: digest, RequestJSON: raw, TraceContext: telemetry.Capture(ctx)})
	if err != nil {
		if errors.Is(err, platformruntime.ErrIdempotencyConflict) {
			return empty, knowledge.ErrIndexTaskConflict
		}
		return empty, err
	}
	if !created.Replayed {
		if err := p.record(tx, actor, scope, "knowledge.index.requested", map[string]any{"run_id": created.Run.ID, "mode": request.Mode, "installation_id": target.InstallationID, "policy_hash": snapshot.Hash}); err != nil {
			return empty, err
		}
	}
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return knowledge.IndexTaskReceipt{SchemaVersion: "knowledge-index-task/v1", RunID: created.Run.ID, Status: string(created.Run.Status), Replayed: created.Replayed}, nil
}
