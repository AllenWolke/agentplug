package knowledge

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type pipelineAuthorityFixture struct {
	facts    []DocumentFact
	calls    int
	revokeAt int
}

func (a *pipelineAuthorityFixture) ResolveCurrentDocuments(context.Context, sharedkernel.Scope, string) ([]DocumentFact, error) {
	a.calls++
	if a.revokeAt > 0 && a.calls >= a.revokeAt {
		return nil, nil
	}
	return append([]DocumentFact(nil), a.facts...), nil
}

type pipelineModelFixture struct {
	calls     int
	invalid   string
	onRewrite func()
}

func (m *pipelineModelFixture) Rewrite(_ context.Context, _ sharedkernel.Scope, query string) (QueryRewrite, error) {
	m.calls++
	if m.onRewrite != nil {
		m.onRewrite()
	}
	if m.invalid == "rewrite" {
		return QueryRewrite{}, nil
	}
	return QueryRewrite{Text: "recovery procedure", QueryStageReceipt: QueryStageReceipt{ModelVersionID: "chat", PromptVersionID: "rewrite-v1", InvocationID: "rewrite-call"}}, nil
}
func (m *pipelineModelFixture) EmbedQuery(context.Context, sharedkernel.Scope, string) (QueryEmbedding, error) {
	m.calls++
	vector := []float32{1, 0}
	if m.invalid == "embedding" {
		vector = []float32{0, 0}
	}
	return QueryEmbedding{Vector: vector, QueryStageReceipt: QueryStageReceipt{ModelVersionID: "embedding-v1", InvocationID: "embedding-call"}}, nil
}
func (m *pipelineModelFixture) Rerank(_ context.Context, _ sharedkernel.Scope, query string, chunks []HybridChunk) (QueryReranking, error) {
	m.calls++
	if query != "recovery procedure" {
		return QueryReranking{}, ErrInvalidQueryStage
	}
	scores := []QueryChunkScore{}
	for _, chunk := range chunks {
		if chunk.DocumentID != "visible" {
			return QueryReranking{}, errors.New("unauthorized body sent to reranker")
		}
		score := .1
		if chunk.ID == "preferred" {
			score = .9
		}
		scores = append(scores, QueryChunkScore{ChunkID: chunk.ID, Score: score})
	}
	// Mutating input must not alter canonical content returned to the caller.
	chunks[0].Text = "model-invented body"
	switch m.invalid {
	case "unknown":
		scores[0].ChunkID = "invented"
	case "duplicate":
		scores[0].ChunkID = scores[1].ChunkID
	case "partial":
		scores = scores[:1]
	case "nan":
		scores[0].Score = math.NaN()
	case "range":
		scores[0].Score = 1.1
	}
	return QueryReranking{Scores: scores, QueryStageReceipt: QueryStageReceipt{ModelVersionID: "chat", PromptVersionID: "rerank-v1", InvocationID: "rerank-call"}}, nil
}

func TestPostgresGovernedQueryPipeline(t *testing.T) {
	p, s := projectionFixture(t)
	ctx := context.Background()
	g := Generation{ID: "pipeline-g1", EmbeddingModelVersion: "embedding-v1", Dimensions: 2}
	chunks := []ProjectedChunk{
		{Chunk: Chunk{ID: "first", DocumentID: "visible", DocumentVersion: "v1", Text: "recovery procedure recovery"}, ACLRevision: "acl1", Embedding: []float32{1, 0}},
		{Chunk: Chunk{ID: "preferred", DocumentID: "visible", DocumentVersion: "v1", Text: "procedure recovery steps"}, ACLRevision: "acl1", Embedding: []float32{.8, .6}},
		{Chunk: Chunk{ID: "private", DocumentID: "private", DocumentVersion: "v1", Text: "private recovery procedure"}, ACLRevision: "acl1", Embedding: []float32{1, 0}},
	}
	if err := p.BuildGeneration(ctx, s, g, chunks); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, s, g.ID, 0); err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: s.TenantID, DepartmentID: s.DepartmentID, ApplicationID: s.ApplicationID, AgentInstanceID: "instance", AgentID: "agent", PrincipalID: "user", PrincipalType: "user", InstallationID: "installation", AgentVersionID: "v1", SessionID: "session", RunID: "run", TraceID: "trace", AuthorizationEpoch: 1}
	newPipeline := func() (QueryPipeline, *pipelineAuthorityFixture, *pipelineModelFixture) {
		a := &pipelineAuthorityFixture{facts: []DocumentFact{{ID: "visible", Version: "v1", ACLRevision: "acl1"}}}
		m := &pipelineModelFixture{}
		return QueryPipeline{Retriever: GovernedProjectionRetriever{Projection: p, Authority: a, MaximumCorpus: 10}, Models: m}, a, m
	}
	t.Run("rewrite-hybrid-rerank-topk-and-provenance", func(t *testing.T) {
		pipeline, a, m := newPipeline()
		result, err := pipeline.Search(ctx, scope, s.KnowledgeID, "how to recover?", 1, 2)
		if err != nil || len(result.Chunks) != 1 || result.Chunks[0].ID != "preferred" || result.Chunks[0].Text != "procedure recovery steps" || result.Generation.ID != g.ID || result.Revision != 1 || result.OriginalQuery != "how to recover?" || result.RewrittenQuery != "recovery procedure" || result.RerankingReceipt.PromptVersionID != "rerank-v1" || result.EmbeddingReceipt.ModelVersionID != "embedding-v1" || m.calls != 3 || a.calls != 7 {
			t.Fatalf("pipeline result mismatch: %#v %v model_calls=%d authority_calls=%d", result, err, m.calls, a.calls)
		}
	})
	for _, stage := range []string{"rewrite", "embedding", "unknown", "duplicate", "partial", "nan", "range"} {
		t.Run("invalid-"+stage, func(t *testing.T) {
			pipeline, _, m := newPipeline()
			m.invalid = stage
			result, err := pipeline.Search(ctx, scope, s.KnowledgeID, "how to recover?", 1, 2)
			if !errors.Is(err, ErrInvalidQueryStage) || len(result.Chunks) != 0 {
				t.Fatal("invalid stage exposed content", err)
			}
		})
	}
	for _, stage := range []struct {
		name            string
		revokeAt, calls int
	}{{"before-model", 1, 0}, {"after-rewrite", 2, 1}, {"after-embedding", 3, 2}, {"after-sql", 5, 2}, {"after-rerank", 7, 3}} {
		t.Run("revoke-"+stage.name, func(t *testing.T) {
			pipeline, a, m := newPipeline()
			a.revokeAt = stage.revokeAt
			result, err := pipeline.Search(ctx, scope, s.KnowledgeID, "how to recover?", 1, 2)
			if err == nil || len(result.Chunks) != 0 || m.calls != stage.calls {
				t.Fatalf("revocation leak: %v calls=%d", err, m.calls)
			}
		})
	}
	t.Run("cancel-after-rewrite", func(t *testing.T) {
		pipeline, _, m := newPipeline()
		cancelled, cancel := context.WithCancel(ctx)
		defer cancel()
		m.onRewrite = cancel
		result, err := pipeline.Search(cancelled, scope, s.KnowledgeID, "how to recover?", 1, 2)
		if !errors.Is(err, context.Canceled) || len(result.Chunks) != 0 || m.calls != 1 {
			t.Fatal("cancel continued pipeline", err)
		}
	})
}
