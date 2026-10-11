package main

import (
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/policyasset"
)

func TestKnowledgeAnswerRequiresCompleteGovernedReceiptAndKnownCitations(t *testing.T) {
	request := capability.KnowledgeSearchRequest{Policy: policyasset.Snapshot{PromptVersionID: "prompt-v1", Model: policyasset.ModelPolicy{ModelVersionID: "model-v1"}}}
	models := knowledgeQueryModels{request: request}
	chunks := []knowledge.HybridChunk{{Chunk: knowledge.Chunk{ID: "chunk-1", DocumentID: "doc-1", Text: "canonical evidence"}}}
	for _, mode := range []string{"allowed", "unknown-citation", "duplicate-citation", "empty-answer", "extra-verdict", "missing-usage", "missing-cost", "negative-usage", "wrong-model", "trailing-json", "oversized-answer"} {
		t.Run(mode, func(t *testing.T) {
			result := map[string]any{"text": `{"answer":"complete answer","citation_ids":["chunk-1"]}`, "model_version_id": "model-v1", "invocation_id": "invocation-1", "usage": map[string]any{"input_tokens": 42, "output_tokens": 17}, "billing": map[string]any{"price_version_id": "price-v1", "currency": "USD", "cost_micros": 59}}
			switch mode {
			case "unknown-citation":
				result["text"] = `{"answer":"answer","citation_ids":["private-chunk"]}`
			case "duplicate-citation":
				result["text"] = `{"answer":"answer","citation_ids":["chunk-1","chunk-1"]}`
			case "empty-answer":
				result["text"] = `{"answer":" ","citation_ids":["chunk-1"]}`
			case "extra-verdict":
				result["text"] = `{"answer":"answer","citation_ids":["chunk-1"],"grounding":true}`
			case "missing-usage":
				result["usage"] = map[string]any{"input_tokens": 42}
			case "missing-cost":
				result["billing"] = map[string]any{"price_version_id": "price-v1", "currency": "USD"}
			case "negative-usage":
				result["usage"] = map[string]any{"input_tokens": -1, "output_tokens": 17}
			case "wrong-model":
				result["model_version_id"] = "unapproved-model"
			case "trailing-json":
				result["text"] = result["text"].(string) + ` {}`
			case "oversized-answer":
				result["text"] = `{"answer":"` + strings.Repeat("a", 32769) + `","citation_ids":["chunk-1"]}`
			}
			value, err := parseKnowledgeAnswer(models, result, chunks)
			if mode == "allowed" {
				if err != nil || value.Text != "complete answer" || value.Usage.InputTokens != 42 || value.Billing.CostMicros != 59 {
					t.Fatal("approved answer rejected", err)
				}
			} else if err == nil {
				t.Fatal("invalid answer accepted", mode)
			}
		})
	}
}
