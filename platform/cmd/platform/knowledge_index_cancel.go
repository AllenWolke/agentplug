package main

import (
	"context"
	"errors"
	"strings"

	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (c knowledgeControl) CancelIndex(ctx context.Context, actor sharedkernel.Scope, scope knowledge.ProjectionScope, id string, request knowledge.IndexCancelRequest) (knowledge.IndexTaskDetail, error) {
	empty := knowledge.IndexTaskDetail{}
	p := c.persistence
	if p.db == nil || p.execution == nil {
		return empty, knowledge.ErrCheckpointUnavailable
	}
	if actor.PrincipalType != "user" || id == "" || len(id) > 128 || strings.TrimSpace(id) != id || request.ExpectedRevision == 0 {
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
	run, err := p.execution.GetContext(ctx, id)
	if errors.Is(err, platformruntime.ErrRunNotFound) {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	if err != nil {
		return empty, err
	}
	target, _, incremental, err := indexRunParameters(run)
	if err != nil || run.AgentEndpoint != "" || target != scope {
		return empty, knowledge.ErrIndexTaskNotFound
	}
	pending, changed, err := p.execution.BeginInternalTaskCancellationTx(ctx, tx, run.Scope, request.ExpectedRevision)
	if errors.Is(err, platformruntime.ErrRevisionConflict) || errors.Is(err, platformruntime.ErrInvalidTransition) {
		return empty, knowledge.ErrIndexTaskConflict
	}
	if err != nil {
		return empty, err
	}
	detail := knowledge.IndexTaskDetail{SchemaVersion: "knowledge-index-task-detail/v1", RunID: pending.ID, KnowledgeID: scope.KnowledgeID, Mode: "full", Status: string(pending.Status), Revision: pending.Revision}
	if incremental {
		detail.Mode = "incremental"
	}
	if changed {
		if err := p.record(tx, actor, scope, "knowledge.index.cancel_requested", detail); err != nil {
			return empty, err
		}
	}
	if err := p.authorize(ctx, tx, actor, scope); err != nil {
		return empty, knowledgeControlError(err)
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	if pending.Status == platformruntime.StatusCancelling && pending.LeaseToken == "" {
		// No worker ever claimed this generation. The existing cancellation
		// transaction saves terminal outcome and releases its session together.
		// A failure keeps the committed intent pending for reconciliation.
		if final, err := p.execution.Cancel(pending.ID, pending.Revision); err == nil {
			detail.Status, detail.Revision = string(final.Status), final.Revision
		}
	}
	return detail, nil
}
