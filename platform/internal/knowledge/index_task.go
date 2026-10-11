package knowledge

import (
	"context"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// IndexTaskDriver composes the indexing stages of one trusted, leased task.
// The scheduler owns lease acquisition/renewal and run finalization. It must
// supply current IAM/model/lease guards and transactional audit ports; none of
// these can be reconstructed from browser input or a historical checkpoint.
type IndexTaskDriver struct {
	Coordinator IndexCoordinator
	Embedding   IndexEmbeddingWorker
	// LoadCheckpoint must check live task ownership, IAM and lease before
	// returning body-free persisted state. Empty means no checkpoint yet.
	LoadCheckpoint func(context.Context, sharedkernel.Scope, ProjectionScope) (StoredCheckpoint, error)
}

type IndexTaskResult struct {
	GenerationID   string
	SourceRevision int64
	IndexRevision  int64
	EmbeddedChunks int
	ReusedChunks   int
	Checkpoint     CheckpointReceipt
}

// Run is safe to retry after the shadow build or publication committed but
// the scheduler lost its acknowledgment. Its generation ID is platform-derived
// from the immutable full task owner and collection, never supplied by Agents.
// A newer source or intervening index publication fails rather than being reset.
func (d IndexTaskDriver) Run(ctx context.Context, owner sharedkernel.Scope, scope ProjectionScope, config IndexConfig, incremental bool) (IndexTaskResult, error) {
	empty := IndexTaskResult{}
	if owner.ValidateTrusted() != nil || scope != checkpointTaskScope(owner, scope.KnowledgeID) || !scope.valid() || !config.valid() || d.LoadCheckpoint == nil || d.Coordinator.GuardPublishTx == nil || d.Coordinator.RecordPublish == nil || d.Embedding.CheckCurrent == nil || d.Embedding.SaveCheckpoint == nil || d.Embedding.Models == nil {
		return empty, ErrInvalidProjection
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	stored, err := d.LoadCheckpoint(ctx, owner, scope)
	if err != nil {
		return empty, err
	}
	var plan *IndexPlan
	if len(stored.Payload) != 0 {
		saved, digest, err := checkpointEnvelope(scope, stored.Payload)
		if err != nil {
			return empty, err
		}
		if saved.Config != config || stored.Receipt.RunID != owner.RunID || stored.Receipt.KnowledgeID != scope.KnowledgeID || stored.Receipt.SourceRevision != saved.SourceRevision || stored.Receipt.Revision < 1 || stored.Receipt.Digest != digest {
			return empty, ErrInvalidProjection
		}
		plan, err = d.Coordinator.Restore(ctx, scope, stored.Payload)
		if err != nil {
			return empty, err
		}
	} else {
		if stored.Receipt != (CheckpointReceipt{}) {
			return empty, ErrInvalidProjection
		}
		plan, err = d.Coordinator.Prepare(ctx, scope, config, incremental)
		if err != nil {
			return empty, err
		}
	}
	progress, err := d.Embedding.Complete(ctx, owner, plan)
	if err != nil {
		return empty, err
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return d.Embedding.CheckCurrent(ctx, owner, scope, config.EmbeddingModelVersion, plan.SourceRevision())
	}
	if err := check(); err != nil {
		return empty, err
	}
	hash, err := sourceDigest(struct {
		Owner      sharedkernel.Scope
		Collection ProjectionScope
	}{owner, scope})
	if err != nil {
		return empty, err
	}
	generationID := "index-task-" + hash
	if err := d.Coordinator.BuildOrReplay(ctx, plan, generationID, progress.Vectors); err != nil {
		return empty, err
	}
	if err := check(); err != nil {
		return empty, err
	}
	revision, err := d.Coordinator.PublishOrReplay(ctx, plan, generationID)
	if err != nil {
		return empty, err
	}
	// If cancellation or natural expiry occurred during publication, leave
	// durable state for reconciliation instead of claiming task completion.
	if err := check(); err != nil {
		return empty, err
	}
	return IndexTaskResult{GenerationID: generationID, SourceRevision: plan.SourceRevision(), IndexRevision: revision, EmbeddedChunks: progress.EmbeddedChunks, ReusedChunks: progress.ReusedChunks, Checkpoint: progress.Checkpoint}, nil
}
