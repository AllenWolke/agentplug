package knowledge

import (
	"context"
	"encoding/json"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// IndexEmbeddingPort is supplied by platform composition using the SAME
// governed embedding executor as queries. It never accepts vendor credentials.
type IndexEmbeddingPort interface {
	EmbedIndexChunks(context.Context, sharedkernel.Scope, string, []Chunk) (IndexEmbeddingBatch, error)
}

type IndexEmbeddingBatch struct {
	Vectors     map[string][]float32
	Receipt     QueryStageReceipt
	InputTokens *int64
}

type IndexEmbeddingProgress struct {
	Vectors        map[string][]float32
	Receipts       []QueryStageReceipt
	Checkpoint     CheckpointReceipt
	EmbeddedChunks int
	ReusedChunks   int
}

// IndexEmbeddingWorker completes a trusted source plan, one bounded batch at
// a time. The task driver owns Prepare/Restore, leases, shadow Build/Publish
// and run finalization. Saved checkpoints contain no source bodies.
type IndexEmbeddingWorker struct {
	Models            IndexEmbeddingPort
	BatchSize         int
	MaximumBatchBytes int
	// Must check current management AND independent embedding permission,
	// approved model, live task lease and captured source revision. Required
	// before and after external effects, never inferred from old checkpoints.
	CheckCurrent func(context.Context, sharedkernel.Scope, ProjectionScope, string, int64) error
	// Composition supplies the transactional IAM/lease/audit checkpoint store
	// and holds its checkpoint CAS across calls. An empty acknowledgment fails.
	SaveCheckpoint func(context.Context, sharedkernel.Scope, ProjectionScope, []byte) (CheckpointReceipt, error)
}

func (w IndexEmbeddingWorker) Complete(ctx context.Context, owner sharedkernel.Scope, plan *IndexPlan) (IndexEmbeddingProgress, error) {
	empty := IndexEmbeddingProgress{}
	if w.Models == nil || w.CheckCurrent == nil || w.SaveCheckpoint == nil || w.BatchSize < 1 || w.BatchSize > 128 || w.MaximumBatchBytes < 1 || w.MaximumBatchBytes > 1<<20 || owner.ValidateTrusted() != nil || plan == nil || !plan.prepared || owner.TenantID != plan.scope.TenantID || owner.DepartmentID != plan.scope.DepartmentID || owner.ApplicationID != plan.scope.ApplicationID {
		return empty, ErrInvalidProjection
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return w.CheckCurrent(ctx, owner, plan.scope, plan.config.EmbeddingModelVersion, plan.snapshot.Revision)
	}
	if err := check(); err != nil {
		return empty, err
	}
	work := IndexEmbeddingProgress{Vectors: map[string][]float32{}, ReusedChunks: plan.ReusedChunks()}
	save := func() error {
		if err := check(); err != nil {
			return err
		}
		raw, err := plan.Checkpoint(work.Vectors)
		if err != nil {
			return err
		}
		_, expectedDigest, err := checkpointEnvelope(plan.scope, raw)
		if err != nil {
			return err
		}
		receipt, err := w.SaveCheckpoint(ctx, owner, plan.scope, raw)
		if err != nil {
			return err
		}
		if receipt.RunID != owner.RunID || receipt.KnowledgeID != plan.scope.KnowledgeID || receipt.SourceRevision != plan.snapshot.Revision || receipt.Revision < 1 || receipt.Digest != expectedDigest {
			return ErrCheckpointUnavailable
		}
		work.Checkpoint = receipt
		return check()
	}
	// Persist the captured configuration/source/CAS even if there is nothing
	// to embed (for example an ACL-only incremental change or deletion).
	if err := save(); err != nil {
		return empty, err
	}
	needed := plan.RequiredChunks()
	limit := w.MaximumBatchBytes
	// Leave room for the governed gateway's model/metadata envelope.
	if limit > (1<<20)-1024 {
		limit = (1 << 20) - 1024
	}
	for offset := 0; offset < len(needed); {
		end, bytes := offset, len(`{"texts":[]}`)
		for end < len(needed) && end-offset < w.BatchSize {
			encoded, err := json.Marshal(needed[end].Text)
			if err != nil {
				return empty, ErrInvalidProjection
			}
			size := len(encoded)
			if end > offset {
				size++
			}
			if bytes+size > limit {
				break
			}
			bytes += size
			end++
		}
		if end == offset {
			return empty, ErrCorpusLimit
		}
		if err := check(); err != nil {
			return empty, err
		}
		batch := append([]Chunk(nil), needed[offset:end]...)
		result, err := w.Models.EmbedIndexChunks(ctx, owner, plan.config.EmbeddingModelVersion, batch)
		if err != nil {
			return empty, err
		}
		if err := check(); err != nil {
			return empty, err
		}
		if result.Receipt.ModelVersionID != plan.config.EmbeddingModelVersion || !validQueryReceipt(result.Receipt, false) || len(result.Vectors) != end-offset {
			return empty, ErrInvalidQueryStage
		}
		if plan.config.ChunkingUnit == TokenArtifactUnit {
			documents := map[string]SourceDocument{}
			for _, document := range plan.snapshot.Documents {
				documents[document.ID] = document
			}
			expectedTokens := int64(0)
			for _, chunk := range needed[offset:end] {
				document, found := documents[chunk.DocumentID]
				if !found {
					return empty, ErrSourceCorrupt
				}
				count, err := tokenArtifactCount(document, plan.config)
				if err != nil {
					return empty, err
				}
				expectedTokens += count
			}
			if result.InputTokens == nil || *result.InputTokens != expectedTokens {
				// Counts differing from actual billable usage cannot be used as
				// proof of tokenizer fidelity or absence of silent truncation.
				return empty, ErrInvalidQueryStage
			}
		}
		// Use canonical plan IDs, never a model-mutated input slice or invented
		// output IDs. Validate all vectors BEFORE saving any part of this batch.
		for _, chunk := range needed[offset:end] {
			vector, ok := result.Vectors[chunk.ID]
			if !ok {
				return empty, ErrInvalidQueryStage
			}
			if _, err := vectorLiteral(vector, plan.config.Dimensions); err != nil {
				return empty, err
			}
		}
		for _, chunk := range needed[offset:end] {
			work.Vectors[chunk.ID] = append([]float32(nil), result.Vectors[chunk.ID]...)
		}
		work.EmbeddedChunks += end - offset
		work.Receipts = append(work.Receipts, result.Receipt)
		if err := save(); err != nil {
			return empty, err
		}
		offset = end
	}
	return work, nil
}
