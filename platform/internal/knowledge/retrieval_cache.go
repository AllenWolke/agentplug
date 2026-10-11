package knowledge

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// Only ranking metadata and body digests are cached. Every hit reads canonical
// bodies through current metadata filtering in PostgreSQL; cached text can
// never stand in for a current source or authorization decision.
type cachedRetrieval struct {
	Result      ProjectionResult
	BodyDigests []string
}

func retrievalBodyDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func (r GovernedProjectionRetriever) retrieveProjection(ctx context.Context, scope sharedkernel.Scope, ps ProjectionScope, facts []DocumentFact, model, query string, vector []float32, limit int) (ProjectionResult, error) {
	load := func(ctx context.Context) (ProjectionResult, error) {
		return r.Projection.Search(ctx, ps, facts, model, query, vector, limit, r.MaximumCorpus)
	}
	if r.Cache == nil {
		return load(ctx)
	}
	if scope != r.CacheBoundary.Scope || r.CacheBoundary.PolicyFingerprint == "" || r.CacheBoundary.CorpusFingerprint == "" || r.CacheBoundary.PipelineVersion == "" {
		return ProjectionResult{}, ErrInvalidProjection
	}
	if _, err := documentFactSet(facts); err != nil || len(facts) == 0 {
		return ProjectionResult{}, ErrKnowledgeAuthorityUnavailable
	}
	ordered := append([]DocumentFact(nil), facts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	generation, revision, err := r.Projection.ActiveGeneration(ctx, ps)
	if err != nil {
		return ProjectionResult{}, err
	}
	if generation.EmbeddingModelVersion != model || limit < 1 || limit > 100 || r.MaximumCorpus < 1 || r.MaximumCorpus > 100000 {
		return ProjectionResult{}, ErrInvalidProjection
	}
	if _, err := vectorLiteral(vector, generation.Dimensions); err != nil {
		return ProjectionResult{}, err
	}
	key, err := json.Marshal(struct {
		Boundary             CacheBoundary
		Scope                ProjectionScope
		Facts                []DocumentFact
		Generation           Generation
		Revision             int64
		Query                string
		Vector               []float32
		Limit, MaximumCorpus int
	}{r.CacheBoundary.CacheIdentity(), ps, ordered, generation, revision, query, vector, limit, r.MaximumCorpus})
	if err != nil {
		return ProjectionResult{}, ErrInvalidProjection
	}
	encoded, hit, err := r.Cache.Do(ctx, CacheKey(key), func(ctx context.Context) ([]byte, error) {
		result, err := load(ctx)
		if err != nil {
			return nil, err
		}
		if result.Generation != generation || result.Revision != revision {
			return nil, ErrProjectionConflict
		}
		cached := cachedRetrieval{Result: result}
		for i := range cached.Result.Chunks {
			cached.BodyDigests = append(cached.BodyDigests, retrievalBodyDigest(cached.Result.Chunks[i].Text))
			cached.Result.Chunks[i].Text = ""
		}
		return json.Marshal(cached)
	})
	if err != nil {
		return ProjectionResult{}, err
	}
	var cached cachedRetrieval
	if json.Unmarshal(encoded, &cached) != nil || cached.Result.Generation != generation || cached.Result.Revision != revision || len(cached.Result.Chunks) > limit || len(cached.BodyDigests) != len(cached.Result.Chunks) {
		return ProjectionResult{}, ErrInvalidProjection
	}
	result, err := r.Projection.restoreCachedRetrieval(ctx, ps, ordered, cached)
	result.CacheHit = hit
	return result, err
}

func (p PostgresProjection) restoreCachedRetrieval(ctx context.Context, scope ProjectionScope, facts []DocumentFact, cached cachedRetrieval) (ProjectionResult, error) {
	empty := ProjectionResult{}
	result := cached.Result
	encodedFacts, err := json.Marshal(facts)
	if err != nil {
		return empty, err
	}
	tx, err := p.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var generation Generation
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT g.generation_id,g.embedding_model_version,g.dimensions,a.revision FROM knowledge.active_generations a JOIN knowledge.generations g USING (tenant_id,department_id,application_id,knowledge_id,generation_id) WHERE a.tenant_id=$1 AND a.department_id=$2 AND a.application_id=$3 AND a.knowledge_id=$4 AND g.state='ready' AND g.tokenizer_version=$5`, append(scope.args(), TokenizerVersion)...).Scan(&generation.ID, &generation.EmbeddingModelVersion, &generation.Dimensions, &revision)
	if err != nil {
		return empty, err
	}
	if generation != result.Generation || revision != result.Revision {
		return empty, ErrProjectionConflict
	}
	seen := map[string]bool{}
	for i := range result.Chunks {
		chunk := &result.Chunks[i]
		identity := chunk.DocumentID + "\x00" + chunk.ID
		if chunk.ID == "" || chunk.DocumentID == "" || seen[identity] || chunk.Text != "" || math.IsNaN(chunk.Score) || math.IsInf(chunk.Score, 0) || chunk.Score <= 0 || chunk.LexicalRank < 0 || chunk.VectorRank < 0 {
			return empty, ErrInvalidProjection
		}
		seen[identity] = true
		args := append(scope.args(), generation.ID, string(encodedFacts), chunk.DocumentID, chunk.ID, chunk.DocumentVersion)
		err := tx.QueryRowContext(ctx, visibleChunksSQL+`SELECT body FROM visible WHERE document_id=$7 AND chunk_id=$8 AND document_version=$9`, args...).Scan(&chunk.Text)
		if err != nil {
			return empty, err
		}
		if retrievalBodyDigest(chunk.Text) != cached.BodyDigests[i] {
			return empty, ErrInvalidProjection
		}
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return result, nil
}
