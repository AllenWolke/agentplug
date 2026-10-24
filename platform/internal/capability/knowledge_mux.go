package capability

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/knowledge"
	"sort"
	"strconv"
	"sync"
)

// NewFederatedKnowledgeProvider 组合两个受控来源，不给Agent暴露Provider地址或凭证。
func NewFederatedKnowledgeProvider(local, remote KnowledgeProvider) KnowledgeProvider {
	if remote == nil {
		return local
	}
	return &federatedKnowledgeProvider{local: local, remote: remote}
}

type federatedKnowledgeProvider struct{ local, remote KnowledgeProvider }
type knowledgeSourceResult struct {
	source string
	data   map[string]any
	err    error
}

func (p *federatedKnowledgeProvider) Search(ctx context.Context, actor harnessContext, query knowledgeQuery) (map[string]any, error) {
	if !query.GovernedDocuments || len(query.Documents) == 0 {
		return nil, errKnowledgeDocumentAuthority
	}

	local, remote := query, query
	local.Documents, remote.Documents = nil, nil
	local.Answer, remote.Answer = false, false
	for _, document := range query.Documents {
		if document.ProviderID == "retrievalops" {
			remote.Documents = append(remote.Documents, document)
		} else {
			local.Documents = append(local.Documents, document)
		}
	}
	if len(remote.Documents) == 0 && p.local != nil {
		local.Answer = query.Answer
		return p.local.Search(ctx, actor, local)
	}
	allowed := map[string]string{}
	for _, doc := range query.Documents {
		allowed[doc.ObjectID()] = doc.DocumentVersion
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan knowledgeSourceResult, 2)
	var workers sync.WaitGroup
	start := func(source string, provider KnowledgeProvider, input knowledgeQuery) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if provider == nil {
				results <- knowledgeSourceResult{source: source, err: errors.New("knowledge provider unavailable")}
				return
			}
			data, err := provider.Search(child, actor, input)
			results <- knowledgeSourceResult{source, data, err}
		}()
	}
	if len(local.Documents) > 0 {
		start("platform-knowledge", p.local, local)
	}
	if len(remote.Documents) > 0 {
		start("retrievalops", p.remote, remote)
	}
	go func() { workers.Wait(); close(results) }()
	refs := map[string]map[string]any{}
	scores := map[string]float64{}
	sources, failed := []string{}, []string{}
	var firstFailure error
	for result := range results {
		if result.err != nil {
			var modelError *KnowledgeModelError
			if errors.Is(result.err, errKnowledgeDocumentAuthority) || errors.Is(result.err, knowledge.ErrDocumentValidityUnavailable) || errors.Is(result.err, knowledge.ErrKnowledgeAuthorityChanged) || errors.Is(result.err, knowledge.ErrKnowledgeAuthorityUnavailable) || errors.As(result.err, &modelError) && (modelError.Status == 401 || modelError.Status == 403 || modelError.Status == 402 || modelError.Code == "KNOWLEDGE_VALIDITY_UNAVAILABLE" || modelError.Code == "KNOWLEDGE_VERSION_UNAVAILABLE" || modelError.Code == "KNOWLEDGE_VERSION_CHANGED") {
				cancel()
				return nil, result.err
			}
			failed = append(failed, result.source)
			if firstFailure == nil {
				firstFailure = result.err
			}
			continue
		}
		sources = append(sources, result.source)
		items, _ := result.data["references"].([]map[string]any)
		for rank, item := range items {
			key := stringValue(item["source"]) + "/" + stringValue(item["provider_knowledge_base_id"]) + "/" + stringValue(item["provider_document_id"]) + "/" + stringValue(item["clause_or_chunk_id"])
			documentID := stringValue(item["source"]) + "/" + stringValue(item["provider_knowledge_base_id"]) + "/" + stringValue(item["provider_document_id"])
			if stringValue(item["source"]) != result.source || allowed[documentID] == "" || stringValue(item["document_version"]) != allowed[documentID] || stringValue(item["clause_or_chunk_id"]) == "" || stringValue(item["content"]) == "" {
				cancel()
				return nil, errors.New("knowledge source returned untraceable evidence")
			}
			copy := map[string]any{}
			for k, v := range item {
				copy[k] = v
			}
			copy["provider_retrieval_score"] = item["retrieval_score"]
			copy["provider_chunk_id"] = item["clause_or_chunk_id"]
			copy["clause_or_chunk_id"] = fmt.Sprintf("ref-%x", sha256.Sum256([]byte(key)))
			refs[key] = copy
			scores[key] += 1 / float64(60+rank+1)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, firstFailure
	}
	keys := make([]string, 0, len(refs))
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if scores[keys[i]] == scores[keys[j]] {
			return keys[i] < keys[j]
		}
		return scores[keys[i]] > scores[keys[j]]
	})
	out := []map[string]any{}
	for _, key := range keys {
		refs[key]["retrieval_score"] = scores[key]
		out = append(out, refs[key])
		if len(out) >= query.TopK {
			break
		}
	}
	sort.Strings(sources)
	sort.Strings(failed)
	data := map[string]any{"references": out, "retrieved_sources": sources, "failed_sources": failed, "partial_degraded": len(failed) > 0, "request_id": actor.RequestID, "fusion_version": "authorized-source-rrf-v1", "candidate_count": strconv.Itoa(len(refs))}
	if query.Answer {
		return answerKnowledgeReferences(ctx, query, data)
	}
	return data, nil
}
