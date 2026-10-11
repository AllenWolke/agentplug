package main

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// Composition adapter for an authenticated index task. Calls the platform's
// governed model callback, never an HTTP vendor client or model database.
type knowledgeIndexEmbeddings struct {
	scope   sharedkernel.Scope
	request capability.KnowledgeSearchRequest
}

func (m knowledgeIndexEmbeddings) EmbedIndexChunks(ctx context.Context, scope sharedkernel.Scope, modelVersion string, chunks []knowledge.Chunk) (knowledge.IndexEmbeddingBatch, error) {
	empty := knowledge.IndexEmbeddingBatch{}
	if scope != m.scope || scope.ValidateTrusted() != nil || m.request.ModelCall == nil || len(chunks) == 0 || len(chunks) > 128 {
		return empty, knowledge.ErrInvalidQueryStage
	}
	selected, err := m.request.Policy.Model.ForEmbedding()
	if err != nil || selected.ModelVersionID != modelVersion {
		return empty, knowledge.ErrInvalidQueryStage
	}
	texts := make([]string, len(chunks))
	seen := map[string]bool{}
	bytes := 0
	for i, chunk := range chunks {
		if chunk.ID == "" || seen[chunk.ID] || strings.TrimSpace(chunk.Text) == "" {
			return empty, knowledge.ErrInvalidQueryStage
		}
		seen[chunk.ID] = true
		texts[i] = chunk.Text
		bytes += len(chunk.Text)
	}
	if bytes > 1<<20 {
		return empty, knowledge.ErrCorpusLimit
	}
	result, err := m.request.ModelCall(ctx, "embed", map[string]any{"texts": texts, "input_purpose": "document"})
	if err != nil {
		return empty, err
	}
	receipt, err := (knowledgeQueryModels{scope: m.scope, request: m.request}).receipt(result, true)
	if err != nil {
		return empty, err
	}
	raw, err := json.Marshal(result["vectors"])
	var vectors [][]float32
	if err != nil || json.Unmarshal(raw, &vectors) != nil || len(vectors) != len(chunks) {
		return empty, knowledge.ErrInvalidQueryStage
	}
	mapped := make(map[string][]float32, len(chunks))
	for i, chunk := range chunks {
		mapped[chunk.ID] = append([]float32(nil), vectors[i]...)
	}
	var inputTokens *int64
	if raw, err := json.Marshal(result["usage"]); err == nil {
		var usage map[string]json.RawMessage
		if json.Unmarshal(raw, &usage) == nil {
			var count int64
			if tokenRaw, ok := usage["input_tokens"]; ok && json.Unmarshal(tokenRaw, &count) == nil && count >= 0 {
				inputTokens = &count
			}
		}
	}
	return knowledge.IndexEmbeddingBatch{Vectors: mapped, Receipt: receipt, InputTokens: inputTokens}, nil
}
