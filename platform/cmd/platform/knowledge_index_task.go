package main

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// indexTask composes an already authenticated, leased platform task. The
// scheduler supplies callbacks bound to that task's signed execution context;
// this factory neither creates business authority nor exposes lease secrets.
func (p knowledgePersistence) indexTask(actor sharedkernel.Scope, scope knowledge.ProjectionScope, token string, revision uint64, models knowledgeIndexEmbeddings) (knowledge.IndexTaskDriver, error) {
	empty := knowledge.IndexTaskDriver{}
	if p.db == nil || p.iam == nil || p.execution == nil || p.audit == nil || actor.ValidateTrusted() != nil || models.scope != actor || models.request.ModelCheck == nil || models.request.ModelCall == nil || token == "" || revision == 0 || scope.KnowledgeID == "" || scope.TenantID != actor.TenantID || scope.DepartmentID != actor.DepartmentID || scope.ApplicationID != actor.ApplicationID {
		return empty, knowledge.ErrInvalidProjection
	}
	selected, err := models.request.Policy.Model.ForEmbedding()
	if err != nil {
		return empty, err
	}
	guard := func(ctx context.Context, tx *sql.Tx) error {
		if err := p.authorize(ctx, tx, actor, scope); err != nil {
			return err
		}
		if err := p.execution.CheckTaskLeaseTx(ctx, tx, actor, token, revision); err != nil {
			return err
		}
		if err := models.request.ModelCheck(ctx, "embed"); err != nil {
			return err
		}
		// Approved-model lookup must not extend IAM or lease natural expiry.
		if err := p.authorize(ctx, tx, actor, scope); err != nil {
			return err
		}
		return p.execution.CheckTaskLeaseTx(ctx, tx, actor, token, revision)
	}
	coordinator := p.index(actor)
	if p.indexCompensation != nil {
		binding, err := p.indexCompensation.Bind(actor)
		if err != nil {
			return empty, err
		}
		coordinator.Cancellation = binding
	}
	coordinator.GuardPublishTx = func(ctx context.Context, tx *sql.Tx, target knowledge.ProjectionScope) error {
		if target != scope {
			return identity.ErrPermissionDenied
		}
		return guard(ctx, tx)
	}
	recordPublish := coordinator.RecordPublish
	coordinator.RecordPublish = func(ctx context.Context, tx *sql.Tx, target knowledge.ProjectionScope, generation string, sourceRevision, indexRevision int64) error {
		if target != scope {
			return identity.ErrPermissionDenied
		}
		if err := guard(ctx, tx); err != nil {
			return err
		}
		return recordPublish(ctx, tx, target, generation, sourceRevision, indexRevision)
	}
	checkpoints := p.checkpoints(scope)
	checkpoints.GuardTx = func(ctx context.Context, tx *sql.Tx, current sharedkernel.Scope, currentToken string, currentRevision uint64) error {
		if current != actor || currentToken != token || currentRevision != revision {
			return identity.ErrPermissionDenied
		}
		return guard(ctx, tx)
	}
	// This CAS is confined to one worker invocation. A restarted invocation
	// obtains the durable revision through Load, including exact replay receipts.
	expected := int64(0)
	driver := knowledge.IndexTaskDriver{Coordinator: coordinator, LoadCheckpoint: func(ctx context.Context, current sharedkernel.Scope, target knowledge.ProjectionScope) (knowledge.StoredCheckpoint, error) {
		if current != actor || target != scope {
			return knowledge.StoredCheckpoint{}, identity.ErrPermissionDenied
		}
		saved, err := checkpoints.Load(ctx, current, scope.KnowledgeID, token, revision)
		if errors.Is(err, knowledge.ErrCheckpointNotFound) {
			expected = 0
			return knowledge.StoredCheckpoint{}, nil
		}
		if err == nil {
			expected = saved.Receipt.Revision
		}
		return saved, err
	}}
	driver.Embedding = knowledge.IndexEmbeddingWorker{Models: models, BatchSize: 16, MaximumBatchBytes: 128 << 10, CheckCurrent: func(ctx context.Context, current sharedkernel.Scope, target knowledge.ProjectionScope, model string, sourceRevision int64) error {
		if current != actor || target != scope || model != selected.ModelVersionID {
			return identity.ErrPermissionDenied
		}
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := guard(ctx, tx); err != nil {
			return err
		}
		if err := coordinator.Source.CheckRevisionTx(ctx, tx, scope, sourceRevision); err != nil {
			return err
		}
		if err := guard(ctx, tx); err != nil {
			return err
		}
		return tx.Commit()
	}, SaveCheckpoint: func(ctx context.Context, current sharedkernel.Scope, target knowledge.ProjectionScope, raw []byte) (knowledge.CheckpointReceipt, error) {
		if current != actor || target != scope {
			return knowledge.CheckpointReceipt{}, identity.ErrPermissionDenied
		}
		saved, err := checkpoints.Save(ctx, current, scope.KnowledgeID, token, revision, expected, raw)
		if err == nil {
			expected = saved.Receipt.Revision
		}
		return saved.Receipt, err
	}}
	return driver, nil
}
