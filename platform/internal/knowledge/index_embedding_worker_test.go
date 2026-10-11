package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type indexBudgetModel struct{ calls, maxBytes int }

func (m *indexBudgetModel) EmbedIndexChunks(_ context.Context, _ sharedkernel.Scope, version string, chunks []Chunk) (IndexEmbeddingBatch, error) {
	m.calls++
	texts := []string{}
	vectors := map[string][]float32{}
	for _, chunk := range chunks {
		texts = append(texts, chunk.Text)
		vectors[chunk.ID] = []float32{1, .5}
	}
	raw, _ := json.Marshal(map[string]any{"texts": texts})
	if len(raw) > m.maxBytes {
		return IndexEmbeddingBatch{}, ErrCorpusLimit
	}
	return IndexEmbeddingBatch{Vectors: vectors, Receipt: QueryStageReceipt{ModelVersionID: version, InvocationID: "fixture"}}, nil
}

func TestIndexEmbeddingWorkerBoundsSerializedBatchBytes(t *testing.T) {
	owner := cacheFixtureScope()
	scope := ProjectionScope{TenantID: owner.TenantID, DepartmentID: owner.DepartmentID, ApplicationID: owner.ApplicationID, KnowledgeID: "docs"}
	plan := &IndexPlan{scope: scope, prepared: true, configHash: "config", sourceDigest: "source", snapshot: SourceSnapshot{Revision: 1}, config: IndexConfig{EmbeddingModelVersion: "embedding", Dimensions: 2, WindowRunes: 8, MaximumDocuments: 10, MaximumChunks: 10}}
	for _, id := range []string{"a", "b", "c"} {
		plan.chunks = append(plan.chunks, ProjectedChunk{Chunk: Chunk{ID: id, DocumentID: "doc", DocumentVersion: "1", Text: strings.Repeat("<", 8)}, ACLRevision: "1"})
	}
	for _, limit := range []int{128, 32} {
		model := &indexBudgetModel{maxBytes: limit}
		worker := IndexEmbeddingWorker{Models: model, BatchSize: 128, MaximumBatchBytes: limit, CheckCurrent: func(context.Context, sharedkernel.Scope, ProjectionScope, string, int64) error { return nil }, SaveCheckpoint: func(_ context.Context, _ sharedkernel.Scope, _ ProjectionScope, raw []byte) (CheckpointReceipt, error) {
			_, digest, err := checkpointEnvelope(scope, raw)
			return CheckpointReceipt{RunID: owner.RunID, KnowledgeID: scope.KnowledgeID, Revision: 1, SourceRevision: 1, Digest: digest}, err
		}}
		work, err := worker.Complete(context.Background(), owner, plan)
		if limit == 128 {
			if err != nil || model.calls != 2 || work.EmbeddedChunks != 3 {
				t.Fatal("JSON escaping did not split batch", err, model.calls)
			}
		} else if !errors.Is(err, ErrCorpusLimit) || model.calls != 0 {
			t.Fatal("oversized serialized chunk reached model", err, model.calls)
		}
	}
}
