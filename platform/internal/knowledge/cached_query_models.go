package knowledge

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// CacheBoundary is constructed by platform composition, never from an Agent
// allowlist. The full execution context is checked on every call; the cache
// identity retains user/session/installation/version/epoch and policy/corpus.
type CacheBoundary struct {
	Scope             sharedkernel.Scope
	PolicyFingerprint string
	CorpusFingerprint string
	PipelineVersion   string
}

// CacheIdentity is only a value-cache key, never an authorization scope.
// Run/trace ancestry does not change these pure query transformations. Keep
// session isolation until context-dependent prompts have explicit input keys.
func (b CacheBoundary) CacheIdentity() CacheBoundary {
	b.Scope.RunID = ""
	b.Scope.TraceID = ""
	b.Scope.ParentRunID = ""
	return b
}

type CachedQueryModels struct {
	Models   GovernedQueryModels
	Cache    *StageCache
	Boundary CacheBoundary
	// Check revalidates signed/live execution AND independent model resource
	// authorization and current approved model selection, without invoking it.
	Check func(context.Context, sharedkernel.Scope, string) error
}

func (m CachedQueryModels) stage(ctx context.Context, scope sharedkernel.Scope, stage string, input any, load func(context.Context) ([]byte, error)) ([]byte, bool, error) {
	if m.Models == nil || m.Check == nil || scope != m.Boundary.Scope || scope.ValidateTrusted() != nil || m.Boundary.PolicyFingerprint == "" || m.Boundary.CorpusFingerprint == "" || strings.TrimSpace(m.Boundary.PipelineVersion) == "" {
		return nil, false, ErrInvalidQueryStage
	}
	if err := m.Check(ctx, scope, stage); err != nil {
		return nil, false, err
	}
	encoded, err := json.Marshal(struct {
		Boundary CacheBoundary
		Stage    string
		Input    any
	}{m.Boundary.CacheIdentity(), stage, input})
	if err != nil {
		return nil, false, ErrInvalidQueryStage
	}
	value, hit, err := m.Cache.Do(ctx, CacheKey(encoded), load)
	if err != nil {
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := m.Check(ctx, scope, stage); err != nil {
		return nil, false, err
	}
	return value, hit, nil
}

func (m CachedQueryModels) Rewrite(ctx context.Context, scope sharedkernel.Scope, query string) (QueryRewrite, error) {
	var result QueryRewrite
	encoded, hit, err := m.stage(ctx, scope, "rewrite", query, func(ctx context.Context) ([]byte, error) {
		result, err := m.Models.Rewrite(ctx, scope, query)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(result.Text) == "" || len(result.Text) > 16384 || !validQueryReceipt(result.QueryStageReceipt, true) {
			return nil, ErrInvalidQueryStage
		}
		return json.Marshal(result)
	})
	if err != nil {
		return result, err
	}
	if json.Unmarshal(encoded, &result) != nil {
		return QueryRewrite{}, ErrInvalidQueryStage
	}
	result.CacheHit = hit
	return result, nil
}

func (m CachedQueryModels) EmbedQuery(ctx context.Context, scope sharedkernel.Scope, query string) (QueryEmbedding, error) {
	var result QueryEmbedding
	encoded, hit, err := m.stage(ctx, scope, "embedding", query, func(ctx context.Context) ([]byte, error) {
		result, err := m.Models.EmbedQuery(ctx, scope, query)
		if err != nil {
			return nil, err
		}
		if _, err := vectorLiteral(result.Vector, len(result.Vector)); err != nil || !validQueryReceipt(result.QueryStageReceipt, false) {
			return nil, ErrInvalidQueryStage
		}
		return json.Marshal(result)
	})
	if err != nil {
		return result, err
	}
	if json.Unmarshal(encoded, &result) != nil {
		return QueryEmbedding{}, ErrInvalidQueryStage
	}
	result.CacheHit = hit
	return result, nil
}

// Only scores/receipts are cached, never canonical document bodies. SQL
// retrieval and current-source fences still run for every query.
func (m CachedQueryModels) Rerank(ctx context.Context, scope sharedkernel.Scope, query string, chunks []HybridChunk) (QueryReranking, error) {
	var result QueryReranking
	encoded, hit, err := m.stage(ctx, scope, "reranking", struct {
		Query  string
		Chunks []HybridChunk
	}{query, chunks}, func(ctx context.Context) ([]byte, error) {
		result, err := m.Models.Rerank(ctx, scope, query, append([]HybridChunk(nil), chunks...))
		if err != nil {
			return nil, err
		}
		if _, err := validatedRerankingScores(result, chunks); err != nil {
			return nil, err
		}
		return json.Marshal(result)
	})
	if err != nil {
		return result, err
	}
	if json.Unmarshal(encoded, &result) != nil {
		return QueryReranking{}, ErrInvalidQueryStage
	}
	if _, err := validatedRerankingScores(result, chunks); err != nil {
		return QueryReranking{}, err
	}
	result.CacheHit = hit
	return result, nil
}
