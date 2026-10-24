package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (c knowledgeControl) QueryIndexReceipt(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, installation, key string) (knowledge.IndexRecoveryReceipt, error) {
	empty := knowledge.IndexRecoveryReceipt{}
	p := c.persistence
	if p.db == nil || p.execution == nil {
		return empty, knowledge.ErrCheckpointUnavailable
	}
	if actor.Validate() != nil || actor.PrincipalType != "user" || installation == "" || len(installation) > 128 || strings.TrimSpace(installation) != installation || len(key) < 8 || len(key) > 128 || strings.TrimSpace(key) != key {
		return empty, knowledge.ErrInvalidProjection
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	run, err := p.execution.FindInternalTaskTx(ctx, tx, actor, installation, key)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	if errors.Is(err, platformruntime.ErrIdempotencyConflict) {
		return empty, knowledge.ErrIndexTaskConflict
	}
	if err != nil {
		return empty, err
	}
	target, config, incremental, err := indexRunParameters(run)
	if err != nil || target != scope || run.AgentEndpoint != "" || run.Scope.InstallationID != installation || run.IdempotencyKey != key || run.Scope.PrincipalID != actor.PrincipalID || run.Scope.PrincipalType != actor.PrincipalType {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	var command contract.ExecuteRequest
	if json.Unmarshal(run.RequestJSON, &command) != nil || command.ProtocolVersion != contract.ProtocolVersion || command.Operation != "invoke" || command.IdempotencyKey != key || command.Scope.RunID != run.ID || command.Scope.PrincipalID != run.Scope.PrincipalID || command.Scope.PrincipalType != run.Scope.PrincipalType || command.Scope.InstallationID != installation || command.Scope.AgentVersionID != run.AgentVersionID || command.Scope.TenantID != scope.TenantID || command.Scope.DepartmentID != scope.DepartmentID || command.Scope.ApplicationID != scope.ApplicationID {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	request := knowledge.IndexTaskRequest{InstallationID: installation, IdempotencyKey: key, Mode: "full",
		Config: knowledge.IndexSettings{Dimensions: config.Dimensions, WindowRunes: config.WindowRunes, OverlapRunes: config.OverlapRunes, MaximumDocuments: config.MaximumDocuments, MaximumChunks: config.MaximumChunks, ChunkingUnit: config.ChunkingUnit, TokenizerID: config.TokenizerID, TokenizerRevision: config.TokenizerRevision, TokenLimit: config.TokenLimit}}
	if incremental {
		request.Mode = "incremental"
	}
	receipt := knowledge.IndexRecoveryReceipt{SchemaVersion: "knowledge-index-recovery/v1", Scope: scope,
		RunID: run.ID, Status: string(run.Status), Revision: run.Revision, AgentVersionID: run.AgentVersionID,
		Request: request, EmbeddingModelVersion: config.EmbeddingModelVersion}
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return receipt, nil
}
