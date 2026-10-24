package knowledge

import (
	"context"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type fencedRankingFixture struct {
	pipelineModelFixture
	boundedCalls int
}

func (m *fencedRankingFixture) Rerank(context.Context, sharedkernel.Scope, string, []HybridChunk) (QueryReranking, error) {
	return QueryReranking{}, ErrInvalidQueryStage // Dropping the fence is an error.
}

func (m *fencedRankingFixture) RerankWithCheck(_ context.Context, _ sharedkernel.Scope, _ string, chunks []HybridChunk, check func() error) (QueryReranking, error) {
	m.boundedCalls++
	if err := check(); err != nil {
		return QueryReranking{}, err
	}
	return QueryReranking{Scores: []QueryChunkScore{{ChunkID: chunks[0].ID, Score: 0.9}}, QueryStageReceipt: QueryStageReceipt{ModelVersionID: "chat", PromptVersionID: "prompt", InvocationID: "batch-1", InvocationIDs: []string{"batch-1", "batch-2"}}}, nil
}

func TestCachedQueryModelsPreservesBatchFenceReceiptsAndCurrentRevocation(t *testing.T) {
	scope := cacheFixtureScope()
	models := &fencedRankingFixture{}
	m := CachedQueryModels{Models: models, Cache: NewStageCache(8, 1<<20, time.Minute), Boundary: CacheBoundary{Scope: scope, PolicyFingerprint: "policy", CorpusFingerprint: "corpus", PipelineVersion: "bounded-v1"}, Check: func(context.Context, sharedkernel.Scope, string) error { return nil }}
	chunks := []HybridChunk{{Chunk: Chunk{ID: "canonical", Text: "complete evidence"}}}
	checks := 0
	revoked := false
	fence := func() error {
		checks++
		if revoked {
			return ErrKnowledgeAuthorityChanged
		}
		return nil
	}
	for i := 0; i < 2; i++ {
		result, err := m.RerankWithCheck(context.Background(), scope, "question", chunks, fence)
		if err != nil || result.CacheHit != (i == 1) || len(result.InvocationIDs) != 2 || result.InvocationIDs[1] != "batch-2" {
			t.Fatal("batch fence or complete receipts lost", result, err)
		}
	}
	if models.boundedCalls != 1 || checks != 5 {
		t.Fatal("fence bypassed or cached call repeated", models.boundedCalls, checks)
	}
	revoked = true
	if result, err := m.RerankWithCheck(context.Background(), scope, "question", chunks, fence); err == nil || len(result.Scores) != 0 || models.boundedCalls != 1 {
		t.Fatal("cached revoked document disclosed", result, err)
	}
}

func TestQueryReceiptsRequireExactBoundedInvocationIdentities(t *testing.T) {
	base := QueryStageReceipt{ModelVersionID: "chat", PromptVersionID: "prompt", InvocationID: "batch-1"}
	if !validQueryReceipt(base, true) {
		t.Fatal("legacy receipt rejected")
	}
	for _, ids := range [][]string{{"batch-2", "batch-1"}, {"batch-1", "batch-1"}, {"batch-1", ""}, make([]string, 101)} {
		copy := base
		copy.InvocationIDs = ids
		if validQueryReceipt(copy, true) {
			t.Fatal("invalid batch identity accepted", ids)
		}
	}
	base.InvocationIDs = []string{"batch-1", "batch-2"}
	if !validQueryReceipt(base, true) {
		t.Fatal("complete batch receipt rejected")
	}
}
