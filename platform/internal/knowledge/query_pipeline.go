package knowledge

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

var ErrInvalidQueryStage = errors.New("invalid governed knowledge query stage")

// Composition supplies model calls through the platform's governed executor,
// including approved Prompt/model targets, budget, cancellation and usage.
// Business Agents cannot supply these implementations or authorization facts.
type GovernedQueryModels interface {
	Rewrite(context.Context, sharedkernel.Scope, string) (QueryRewrite, error)
	EmbedQuery(context.Context, sharedkernel.Scope, string) (QueryEmbedding, error)
	Rerank(context.Context, sharedkernel.Scope, string, []HybridChunk) (QueryReranking, error)
}

type QueryStageReceipt struct {
	ModelVersionID  string
	PromptVersionID string
	InvocationID    string
	CacheHit        bool
}
type QueryRewrite struct {
	Text string
	QueryStageReceipt
}
type QueryEmbedding struct {
	Vector []float32
	QueryStageReceipt
}
type QueryChunkScore struct {
	ChunkID string
	Score   float64
}
type QueryReranking struct {
	Scores []QueryChunkScore
	QueryStageReceipt
}
type QueryPipelineResult struct {
	ProjectionResult
	OriginalQuery    string
	RewrittenQuery   string
	RewriteReceipt   QueryStageReceipt
	EmbeddingReceipt QueryStageReceipt
	RerankingReceipt QueryStageReceipt
	RerankingScores  map[string]float64
}

type QueryPipeline struct {
	Retriever GovernedProjectionRetriever
	Models    GovernedQueryModels
}

func validQueryReceipt(r QueryStageReceipt, prompt bool) bool {
	return strings.TrimSpace(r.ModelVersionID) != "" && strings.TrimSpace(r.InvocationID) != "" && (!prompt || strings.TrimSpace(r.PromptVersionID) != "")
}

func validatedRerankingScores(ranking QueryReranking, chunks []HybridChunk) (map[string]float64, error) {
	if !validQueryReceipt(ranking.QueryStageReceipt, true) || len(chunks) == 0 || len(chunks) > 100 || len(ranking.Scores) != len(chunks) {
		return nil, ErrInvalidQueryStage
	}
	allowed := make(map[string]bool, len(chunks))
	for _, chunk := range chunks {
		if chunk.ID == "" || allowed[chunk.ID] {
			return nil, ErrInvalidQueryStage
		}
		allowed[chunk.ID] = true
	}
	scores := make(map[string]float64, len(ranking.Scores))
	for _, item := range ranking.Scores {
		_, duplicate := scores[item.ChunkID]
		if !allowed[item.ChunkID] || duplicate || math.IsNaN(item.Score) || math.IsInf(item.Score, 0) || item.Score < 0 || item.Score > 1 {
			return nil, ErrInvalidQueryStage
		}
		scores[item.ChunkID] = item.Score
	}
	return scores, nil
}

func documentFactSet(facts []DocumentFact) (map[string]DocumentFact, error) {
	set := make(map[string]DocumentFact, len(facts))
	for _, fact := range facts {
		if fact.ID == "" || fact.Version == "" || fact.ACLRevision == "" || set[fact.ID].ID != "" {
			return nil, ErrInvalidProjection
		}
		set[fact.ID] = fact
	}
	return set, nil
}

// Search carries immutable provenance through rewriting, SQL hybrid candidate
// retrieval and reranking. Every external stage is fenced by current authority.
// No stage may expand the authorized corpus or replace a retrieved chunk body.
func (p QueryPipeline) Search(ctx context.Context, scope sharedkernel.Scope, knowledgeID, query string, topK, candidateLimit int) (QueryPipelineResult, error) {
	empty := QueryPipelineResult{}
	if p.Models == nil || p.Retriever.Authority == nil || scope.ValidateTrusted() != nil || knowledgeID == "" || len(knowledgeID) > 256 || strings.TrimSpace(query) == "" || len(query) > 16384 || topK < 1 || candidateLimit < topK || candidateLimit > 100 {
		return empty, ErrInvalidQueryStage
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	initial, err := p.Retriever.Authority.ResolveCurrentDocuments(ctx, scope, knowledgeID)
	if err != nil {
		return empty, err
	}
	facts, err := documentFactSet(initial)
	if err != nil || len(facts) == 0 {
		return empty, ErrKnowledgeAuthorityUnavailable
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := p.Retriever.Authority.ResolveCurrentDocuments(ctx, scope, knowledgeID)
		if err != nil {
			return err
		}
		set, err := documentFactSet(current)
		if err != nil {
			return err
		}
		if len(set) != len(facts) {
			return ErrKnowledgeAuthorityChanged
		}
		for id, fact := range facts {
			if set[id] != fact {
				return ErrKnowledgeAuthorityChanged
			}
		}
		return nil
	}
	rewrite, err := p.Models.Rewrite(ctx, scope, query)
	if err != nil {
		return empty, err
	}
	if strings.TrimSpace(rewrite.Text) == "" || len(rewrite.Text) > 16384 || !validQueryReceipt(rewrite.QueryStageReceipt, true) {
		return empty, ErrInvalidQueryStage
	}
	if err := check(); err != nil {
		return empty, err
	}
	embedding, err := p.Models.EmbedQuery(ctx, scope, rewrite.Text)
	if err != nil {
		return empty, err
	}
	if _, err := vectorLiteral(embedding.Vector, len(embedding.Vector)); err != nil || !validQueryReceipt(embedding.QueryStageReceipt, false) {
		return empty, ErrInvalidQueryStage
	}
	if err := check(); err != nil {
		return empty, err
	}
	projection, err := p.Retriever.Retrieve(ctx, scope, knowledgeID, embedding.ModelVersionID, rewrite.Text, embedding.Vector, candidateLimit)
	if err != nil {
		return empty, err
	}
	if err := check(); err != nil {
		return empty, err
	}
	result := QueryPipelineResult{ProjectionResult: projection, OriginalQuery: query, RewrittenQuery: rewrite.Text, RewriteReceipt: rewrite.QueryStageReceipt, EmbeddingReceipt: embedding.QueryStageReceipt}
	if len(projection.Chunks) == 0 {
		return result, nil
	}
	// Copy the slice: a model implementation must not overwrite canonical SQL
	// chunk bodies, versions or references through its argument.
	ranking, err := p.Models.Rerank(ctx, scope, rewrite.Text, append([]HybridChunk(nil), projection.Chunks...))
	if err != nil {
		return empty, err
	}
	scores, err := validatedRerankingScores(ranking, projection.Chunks)
	if err != nil {
		return empty, err
	}
	if err := check(); err != nil {
		return empty, err
	}
	result.Chunks = append([]HybridChunk(nil), projection.Chunks...)
	sort.SliceStable(result.Chunks, func(i, j int) bool {
		return scores[result.Chunks[i].ID] > scores[result.Chunks[j].ID]
	})
	if len(result.Chunks) > topK {
		result.Chunks = result.Chunks[:topK]
	}
	result.RerankingReceipt = ranking.QueryStageReceipt
	result.RerankingScores = make(map[string]float64, len(result.Chunks))
	for _, chunk := range result.Chunks {
		result.RerankingScores[chunk.ID] = scores[chunk.ID]
	}
	return result, nil
}
