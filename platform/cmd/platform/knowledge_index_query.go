package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (c knowledgeControl) QueryIndex(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, id string) (knowledge.IndexTaskDetail, error) {
	empty := knowledge.IndexTaskDetail{}
	p := c.persistence
	if p.db == nil || p.execution == nil {
		return empty, knowledge.ErrCheckpointUnavailable
	}
	if actor.PrincipalType != "user" || id == "" || len(id) > 128 || strings.TrimSpace(id) != id {
		return empty, knowledge.ErrInvalidProjection
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	// Authorize before looking up IDs; unknown and foreign tasks have the same
	// response. Hold IAM continuity until the body-free response is assembled.
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	run, err := p.execution.GetContext(ctx, id)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	if err != nil {
		return empty, err
	}
	target, _, incremental, err := indexRunParameters(run)
	if err != nil || run.AgentEndpoint != "" || target != scope || run.ID != id {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	detail := knowledge.IndexTaskDetail{SchemaVersion: "knowledge-index-task-detail/v1", RunID: run.ID, KnowledgeID: scope.KnowledgeID, Mode: "full", Status: string(run.Status), Revision: run.Revision}
	if incremental {
		detail.Mode = "incremental"
	}
	if run.Status == platformruntime.StatusSucceeded {
		outcome, err := p.execution.GetOutcome(id)
		if err != nil {
			return empty, err
		}
		result, err := indexPublication(outcome, run, scope)
		if err != nil {
			return empty, err
		}
		detail.Result = &result
	}
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return detail, nil
}

func indexPublication(outcome platformruntime.Outcome, run platformruntime.Run, scope knowledge.ProjectionScope) (knowledge.IndexTaskPublication, error) {
	var result knowledge.IndexTaskPublication
	decoder := json.NewDecoder(bytes.NewReader(outcome.OutputJSON))
	decoder.DisallowUnknownFields()
	if len(outcome.OutputJSON) > 8192 || outcome.RunID != run.ID || outcome.Revision != run.Revision || outcome.EventType != "task_completed" || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.SchemaVersion != "knowledge-index-result/v1" || result.KnowledgeID != scope.KnowledgeID || result.GenerationID == "" || len(result.GenerationID) > 256 || result.SourceRevision < 0 || result.IndexRevision < 1 || result.CheckpointRevision < 1 || result.EmbeddedChunks < 0 || result.ReusedChunks < 0 {
		return knowledge.IndexTaskPublication{}, knowledge.ErrInvalidProjection
	}
	return result, nil
}
