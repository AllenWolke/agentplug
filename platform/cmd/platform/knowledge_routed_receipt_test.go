package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/prompt"
)

func routedKnowledgeFixture(t *testing.T) knowledgeQueryModels {
	m := stagedKnowledgeFixture(t)
	m.request.Policy.Model.EmbeddingModelVersionID = "embedding-v1"
	m.request.Policy.Model.EmbeddingModel = "embedding"
	m.request.Policy.Model.EmbeddingProvider = "vectors"
	p := policyasset.ModelRoutingPolicy{Version: "model-routing/v1", SimpleMaxInputTokens: 256, ComplexMinInputTokens: 8192, SimpleMaxOutputTokens: 128, MaxEstimatedMicros: 100000}
	for i, id := range []string{"chat", "alternate"} {
		p.Candidates = append(p.Candidates, policyasset.ModelRouteCandidate{ModelVersionID: id, PriceVersionID: "price-" + id, QualityEvidenceID: "quality-" + id, CapabilitySHA256: strings.Repeat("a", 64), QualityEvidenceSHA256: strings.Repeat("b", 64), MaxComplexity: []string{"complex", "medium"}[i]})
	}
	p.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(m.request.Policy)
	m.request.Policy.Model.Routing = &p
	m.request.ModelReceiptCheck = func(context.Context, string, string) error { return nil }
	return m
}

func TestKnowledgeRoutedRewriteEmbeddingRerankAndAnswerReceipts(t *testing.T) {
	m := routedKnowledgeFixture(t)
	checks, calls := []string{}, 0
	m.request.ModelReceiptCheck = func(_ context.Context, op, version string) error { checks = append(checks, op+":"+version); return nil }
	m.request.ModelCall = func(_ context.Context, operation string, input map[string]any) (map[string]any, error) {
		calls++
		result := map[string]any{"model_version_id": "alternate", "invocation_id": fmt.Sprintf("call-%d", calls)}
		if operation == "embed" {
			result["model_version_id"] = "embedding-v1"
			result["vectors"] = [][]float32{{1, 0}}
			return result, nil
		}
		messages := input["messages"].([]map[string]string)
		text := messages[1]["content"]
		var stage struct {
			Stage string `json:"stage"`
		}
		_ = json.Unmarshal([]byte(text), &stage)
		switch {
		case stage.Stage == "knowledge.rewrite":
			result["text"] = `{"query":"preserved query"}`
		case stage.Stage == "knowledge.rerank":
			result["text"] = `{"scores":[{"chunk_id":"p0","score":0.9}]}`
		default:
			result["text"] = `{"answer":"complete answer","citation_ids":["canonical"]}`
			result["usage"] = map[string]int{"input_tokens": 42, "output_tokens": 17}
			result["billing"] = map[string]any{"price_version_id": "alternate-price", "currency": "USD", "cost_micros": 59}
		}
		return result, nil
	}
	ctx := context.Background()
	chunks := []knowledge.HybridChunk{{Chunk: knowledge.Chunk{ID: "canonical", DocumentID: "doc", Text: "complete evidence"}}}
	r, err := m.Rewrite(ctx, m.scope, "original question")
	if err != nil || r.ModelVersionID != "alternate" {
		t.Fatal("authorized rewrite rejected", err)
	}
	e, err := m.EmbedQuery(ctx, m.scope, r.Text)
	if err != nil || e.ModelVersionID != "embedding-v1" {
		t.Fatal("index binding changed", err)
	}
	rank, err := m.Rerank(ctx, m.scope, r.Text, chunks)
	if err != nil || rank.ModelVersionID != "alternate" {
		t.Fatal("authorized rerank rejected", err)
	}
	answer, err := m.generate(ctx, m.scope, "Answer from complete evidence", 256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseKnowledgeAnswer(m, answer, chunks)
	if err != nil || parsed.Receipt.ModelVersionID != "alternate" || parsed.Billing.PriceVersionID != "alternate-price" {
		t.Fatal("answer still assumed profile primary", err)
	}
	if len(checks) != 4 || calls != 4 {
		t.Fatal("receipt checks resent calls or missed a stage", checks, calls)
	}
	if _, err := m.receipt(map[string]any{"model_version_id": "alternate", "invocation_id": "bad-index"}, true); err == nil {
		t.Fatal("chat route changed embedding model")
	}
	m.request.ModelReceiptCheck = nil
	if _, err := m.receipt(map[string]any{"model_version_id": "alternate", "invocation_id": "forged"}, false); err == nil {
		t.Fatal("routed receipt without trusted verifier accepted")
	}
}

func TestKnowledgeRerankRetainsAndChecksEveryBatchModel(t *testing.T) {
	m := routedKnowledgeFixture(t)
	p, _ := prompt.ParseProgram(m.request.Policy.Prompt.Template)
	p.ExecutionModes = append(p.ExecutionModes, "knowledge-score-vector/v3")
	raw, _ := json.Marshal(p)
	m.request.Policy.Prompt.Template = string(raw)
	m.request.Policy.Model.Routing.ExecutionContextSHA256 = policyasset.RoutingExecutionContextSHA256(m.request.Policy)
	calls := 0
	m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
		calls++
		messages := input["messages"].([]map[string]string)
		var data struct {
			Stage string `json:"stage"`
			Input struct {
				Passages []json.RawMessage `json:"passages"`
			} `json:"input"`
		}
		if json.Unmarshal([]byte(messages[1]["content"]), &data) != nil || data.Stage != "knowledge.rerank" {
			t.Fatal("bad rerank fixture")
		}
		scores := make([]float64, len(data.Input.Passages))
		for i := range scores {
			scores[i] = .9
		}
		text, _ := json.Marshal(map[string]any{"scores": scores})
		version := "alternate"
		if calls == 2 {
			version = "chat"
		}
		return map[string]any{"model_version_id": version, "invocation_id": fmt.Sprintf("batch-%d", calls), "text": string(text)}, nil
	}
	chunks := make([]knowledge.HybridChunk, 9)
	for i := range chunks {
		chunks[i] = knowledge.HybridChunk{Chunk: knowledge.Chunk{ID: fmt.Sprintf("doc-%d", i), Text: "complete evidence"}}
	}
	r, err := m.Rerank(context.Background(), m.scope, "question", chunks)
	if err != nil || calls != 2 || len(r.ModelVersionIDs) != 2 || r.ModelVersionIDs[0] != "alternate" || r.ModelVersionIDs[1] != "chat" {
		t.Fatal("mixed-model provenance lost", r, err, calls)
	}
	m.request.ModelReceiptCheck = func(_ context.Context, _ string, version string) error {
		if version == "chat" {
			return &capability.KnowledgeModelError{Status: 403, Code: "MODEL_ACCESS_DENIED"}
		}
		return nil
	}
	if err := knowledgeCachedReceiptCheck(context.Background(), m.request, false, r.QueryStageReceipt); !errors.Is(err, knowledge.ErrCachedReceiptUnusable) {
		t.Fatal("later batch model revocation ignored", err)
	}
}
