package main

import (
	"context"
	"time"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// executeIndexTask supervises one already authenticated/claimed index task.
// The future scheduler must issue fresh governed callbacks for this precise
// run/lease; request-scoped callbacks cannot be saved for background reuse.
func (p knowledgePersistence) executeIndexTask(ctx context.Context, run platformruntime.Run, scope knowledge.ProjectionScope, config knowledge.IndexConfig, incremental bool, models knowledgeIndexEmbeddings, ttl time.Duration) error {
	if p.execution == nil || p.db == nil || models.scope != run.Scope || models.request.ModelCheck == nil {
		return knowledge.ErrInvalidProjection
	}
	supervisor := execution.InternalTaskSupervisor{Repository: p.execution, LeaseTTL: ttl, Authorize: func(ctx context.Context, actor sharedkernel.Scope) error {
		if actor != run.Scope {
			return identity.ErrPermissionDenied
		}
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := p.authorize(ctx, tx, actor, scope); err != nil {
			return err
		}
		if err := p.execution.CheckTaskLeaseTx(ctx, tx, actor, run.LeaseToken, run.Revision); err != nil {
			return err
		}
		if err := models.request.ModelCheck(ctx, "embed"); err != nil {
			return err
		}
		if err := p.authorize(ctx, tx, actor, scope); err != nil {
			return err
		}
		if err := p.execution.CheckTaskLeaseTx(ctx, tx, actor, run.LeaseToken, run.Revision); err != nil {
			return err
		}
		return tx.Commit()
	}, Execute: func(ctx context.Context, current platformruntime.Run) (map[string]any, error) {
		driver, err := p.indexTask(current.Scope, scope, current.LeaseToken, current.Revision, models)
		if err != nil {
			return nil, err
		}
		// The supervisor owns this precise generation. Only this invocation's
		// trusted lease reaches index preregistration; it is never serialized.
		ctx = sharedkernel.BindExecutionLease(ctx, current.Revision, current.LeaseToken)
		result, err := driver.Run(ctx, current.Scope, scope, config, incremental)
		if err != nil {
			return nil, err
		}
		return map[string]any{"schema_version": "knowledge-index-result/v1", "knowledge_id": scope.KnowledgeID, "generation_id": result.GenerationID, "source_revision": result.SourceRevision, "index_revision": result.IndexRevision, "embedded_chunks": result.EmbeddedChunks, "reused_chunks": result.ReusedChunks, "checkpoint_revision": result.Checkpoint.Revision}, nil
	}}
	return supervisor.Run(ctx, run)
}
