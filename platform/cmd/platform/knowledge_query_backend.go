package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type postgresKnowledgeBackend struct {
	source     *sql.DB
	projection *sql.DB
	authority  capabilityExecutionAuthority
	cache      *knowledge.StageCache
}

const knowledgeQueryPipelineVersion = "hybrid-bm25-pgvector-bounded-rerank-v6-routed-receipts"

func (p postgresKnowledgeBackend) SearchKnowledge(ctx context.Context, scope sharedkernel.Scope, request capability.KnowledgeSearchRequest) (response map[string]any, returnedErr error) {
	defer func() {
		if errors.Is(returnedErr, knowledge.ErrDocumentValidityUnavailable) {
			returnedErr = &capability.KnowledgeModelError{Status: 422, Code: "KNOWLEDGE_VALIDITY_UNAVAILABLE"}
		}
	}()
	if p.source == nil || p.projection == nil || request.ModelCall == nil || len(request.Documents) == 0 || request.Policy.Validate() != nil || request.Policy.ValidateDetails() != nil || scope.ValidateTrusted() != nil {
		return nil, knowledge.ErrInvalidQueryStage
	}
	if request.AsOf != "" {
		if _, err := time.Parse("2006-01-02", request.AsOf); err != nil {
			return nil, knowledge.ErrDocumentValidityUnavailable
		}
	}
	if request.ObservePerformance != nil {
		observedContext, measured := knowledge.WithCacheObservation(ctx)
		ctx = observedContext
		started := time.Now()
		defer func() {
			finished := time.Now()
			lookups, hits, failures := measured.Snapshot()
			mode := request.CacheMode
			if mode == "" {
				mode = "use"
			}
			request.ObservePerformance(ctx, capability.KnowledgeQueryObservation{StartedAt: started, FinishedAt: finished,
				CacheMode: mode, Lookups: lookups, Hits: hits, Failures: failures, Err: returnedErr})
		}()
	}
	var models knowledge.GovernedQueryModels = knowledgeQueryModels{scope: scope, request: request}
	pipelineVersion := knowledgeQueryPipelineVersion
	if (knowledgeQueryModels{request: request}).scoreVectorEnabled() {
		pipelineVersion = "hybrid-bm25-pgvector-score-vector-v7-routed-receipts"
	}
	authority := sourceKnowledgeAuthority{source: knowledge.PostgresSource{DB: p.source}, iam: p.authority, scope: scope, knowledgeID: request.KnowledgeScope, documents: request.Documents, asOf: request.AsOf}
	cache := p.cache
	var cacheBoundary knowledge.CacheBoundary
	switch request.CacheMode {
	case "", "use":
	case "bypass":
		cache = nil
	case "cold":
		cache = knowledge.NewStageCache(256, 16<<20, 5*time.Minute)
	default:
		return nil, knowledge.ErrInvalidQueryStage
	}
	if cache != nil && request.ModelCheck != nil {
		facts, err := authority.ResolveCurrentDocuments(ctx, scope, request.KnowledgeScope)
		if err != nil {
			return nil, err
		}
		if len(facts) == 0 && request.AsOf != "" {
			return nil, knowledge.ErrDocumentValidityUnavailable
		}
		if len(facts) == 0 {
			return nil, knowledge.ErrKnowledgeAuthorityUnavailable
		}
		sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
		generation, revision, err := (knowledge.PostgresProjection{DB: p.projection}).ActiveGeneration(ctx, knowledge.ProjectionScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, KnowledgeID: request.KnowledgeScope})
		if err != nil {
			return nil, err
		}
		policyJSON, err := json.Marshal(struct {
			Policy any
			AsOf   string
		}{request.Policy, request.AsOf})
		if err != nil {
			return nil, knowledge.ErrInvalidQueryStage
		}
		corpusJSON, err := json.Marshal(struct {
			KnowledgeID string
			Documents   []knowledge.DocumentFact
			Generation  knowledge.Generation
			Revision    int64
		}{request.KnowledgeScope, facts, generation, revision})
		if err != nil {
			return nil, knowledge.ErrInvalidQueryStage
		}
		cacheBoundary = knowledge.CacheBoundary{Scope: scope, PolicyFingerprint: knowledge.CacheKey(policyJSON), CorpusFingerprint: knowledge.CacheKey(corpusJSON), PipelineVersion: pipelineVersion}
		if request.ModelCacheBinding != nil {
			binding, err := request.ModelCacheBinding(ctx)
			if err != nil {
				return nil, err
			}
			cacheBoundary.SelectionFingerprint = binding
		}
		models = knowledge.CachedQueryModels{Models: models, Cache: cache, Boundary: cacheBoundary, Check: func(ctx context.Context, current sharedkernel.Scope, stage string) error {
			if current != scope {
				return knowledge.ErrInvalidQueryStage
			}
			operation := "generate"
			if stage == "embedding" {
				operation = "embed"
			}
			return request.ModelCheck(ctx, operation)
		}, CheckReceipt: func(ctx context.Context, current sharedkernel.Scope, stage string, receipt knowledge.QueryStageReceipt) error {
			if current != scope {
				return knowledge.ErrInvalidQueryStage
			}
			return knowledgeCachedReceiptCheck(ctx, request, stage == "embedding", receipt)
		}}
	}
	retriever := knowledge.GovernedProjectionRetriever{Projection: knowledge.PostgresProjection{DB: p.projection}, Authority: authority, MaximumCorpus: 10000}
	if cache != nil && request.ModelCheck != nil {
		retriever.Cache, retriever.CacheBoundary = cache, cacheBoundary
		retriever.CacheBoundary.SelectionFingerprint = ""
	}
	query := knowledge.QueryPipeline{Models: models, Retriever: retriever}
	candidates := request.TopK * 5
	if candidates > 100 {
		candidates = 100
	}
	result, err := query.Search(ctx, scope, request.KnowledgeScope, request.Query, request.TopK, candidates)
	if err != nil {
		return nil, err
	}
	references := make([]map[string]any, 0, len(result.Chunks))
	for _, chunk := range result.Chunks {
		references = append(references, map[string]any{
			"doc_id": "platform-knowledge/" + request.KnowledgeScope + "/" + chunk.DocumentID,
			"source": "platform-knowledge", "provider_knowledge_base_id": request.KnowledgeScope, "provider_document_id": chunk.DocumentID,
			"clause_or_chunk_id": chunk.ID, "content": chunk.Text, "title": chunk.DocumentID, "status": "effective",
			"kb_version": result.Generation.ID, "index_revision": strconv.FormatInt(result.Revision, 10), "document_version": chunk.DocumentVersion,
			"retrieval_score": chunk.Score, "reranking_score": result.RerankingScores[chunk.ID], "lexical_rank": chunk.LexicalRank, "vector_rank": chunk.VectorRank,
			"retriever_version": pipelineVersion,
			"rewrite_cache_hit": result.RewriteReceipt.CacheHit, "embedding_cache_hit": result.EmbeddingReceipt.CacheHit,
			"reranking_cache_hit":   result.RerankingReceipt.CacheHit,
			"retrieval_cache_hit":   result.CacheHit,
			"rewrite_model_version": result.RewriteReceipt.ModelVersionID, "embedding_model_version": result.EmbeddingReceipt.ModelVersionID, "reranking_model_version": result.RerankingReceipt.ModelVersionID,
			"rewrite_invocation_id": result.RewriteReceipt.InvocationID, "embedding_invocation_id": result.EmbeddingReceipt.InvocationID, "reranking_invocation_id": result.RerankingReceipt.InvocationID,
		})
		if len(result.RerankingReceipt.InvocationIDs) > 1 {
			references[len(references)-1]["reranking_invocation_ids"] = append([]string(nil), result.RerankingReceipt.InvocationIDs...)
			references[len(references)-1]["reranking_model_versions"] = append([]string(nil), result.RerankingReceipt.ModelVersionIDs...)
		}
	}
	if err := enrichKnowledgeReferences(ctx, knowledge.PostgresSource{DB: p.source}, knowledge.ProjectionScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, KnowledgeID: request.KnowledgeScope}, references); err != nil {
		return nil, err
	}
	if err := enrichAuthorizedParentContext(ctx, authority, knowledge.ProjectionScope{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, KnowledgeID: request.KnowledgeScope}, references); err != nil {
		return nil, err
	}
	sources := []string{}
	if len(references) > 0 {
		sources = append(sources, "platform-knowledge")
	}
	response = map[string]any{"references": references, "retrieved_sources": sources, "failed_sources": []string{}, "partial_degraded": false, "request_id": request.RequestID}
	if request.Answer {
		answerChunks, err := knowledgeAnswerChunks(result.Chunks, references)
		if err != nil {
			return nil, err
		}
		result.Chunks = answerChunks
		answer, err := p.answerKnowledge(ctx, scope, request, result, authority, cache, cacheBoundary)
		if err != nil {
			return nil, err
		}
		for key, value := range answer {
			response[key] = value
		}
	}
	return response, nil
}

func knowledgeProviderFromConfig(ctx context.Context, config bootstrap.RuntimeConfig, source *sql.DB, authority capabilityExecutionAuthority) (capability.KnowledgeProvider, *sql.DB, error) {
	if config.KnowledgeDatabaseDSN == "" {
		return nil, nil, nil
	}
	if source == nil || authority.identity == nil {
		return nil, nil, errors.New("knowledge source and identity dependencies unavailable")
	}
	projection, err := sqlutil.OpenPostgres(ctx, config.KnowledgeDatabaseDSN)
	if err != nil {
		return nil, nil, errors.New("knowledge PostgreSQL configuration unavailable")
	}
	if err := (knowledge.PostgresProjection{DB: projection}).Ready(ctx); err != nil {
		projection.Close()
		return nil, nil, errors.New("knowledge projection schema or connection unavailable")
	}
	if err := (knowledge.PostgresSource{DB: source}).Ready(ctx); err != nil {
		projection.Close()
		return nil, nil, errors.New("knowledge source schema or connection unavailable")
	}
	return capability.NewGovernedKnowledgeProvider(postgresKnowledgeBackend{source: source, projection: projection, authority: authority, cache: knowledge.NewStageCache(256, 16<<20, 5*time.Minute)}), projection, nil
}
