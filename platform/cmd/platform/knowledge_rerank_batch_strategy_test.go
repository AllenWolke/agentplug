package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/prompt"
)

func TestPublishedSmallRerankBatchesRetainEveryPassageAndReceipt(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			m := stagedKnowledgeFixture(t)
			var p prompt.Program
			if json.Unmarshal([]byte(m.request.Policy.Prompt.Template), &p) != nil {
				t.Fatal("program")
			}
			mode := "knowledge-score-vector/v2"
			if enabled {
				mode = "knowledge-score-vector/v3"
			}
			p.ExecutionModes = append(p.ExecutionModes, mode)
			raw, _ := json.Marshal(p)
			m.request.Policy.Prompt.Template = string(raw)
			m.request.Policy.Model.MaxInputTokens = 32768
			chunks := make([]knowledge.HybridChunk, 25)
			for i := range chunks {
				chunks[i] = knowledge.HybridChunk{Chunk: knowledge.Chunk{ID: fmt.Sprintf("source-%d", i), Text: fmt.Sprintf("完整独立证据%d", i)}}
			}
			calls, total := 0, 0
			m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
				calls++
				messages := input["messages"].([]map[string]string)
				var envelope struct {
					Input struct {
						Passages []rerankPassage `json:"passages"`
					} `json:"input"`
				}
				if json.Unmarshal([]byte(messages[1]["content"]), &envelope) != nil {
					t.Fatal("stage input")
				}
				n := len(envelope.Input.Passages)
				total += n
				if enabled && n > 8 {
					t.Fatal("published batch bound omitted", n)
				}
				var schema struct {
					Properties map[string]struct{ MinItems, MaxItems int }
				}
				if json.Unmarshal(input["response_schema"].(json.RawMessage), &schema) != nil || schema.Properties["scores"].MinItems != n || schema.Properties["scores"].MaxItems != n {
					t.Fatal("schema does not bind actual batch", n)
				}
				scores := make([]float64, n)
				for i := range scores {
					scores[i] = 0.75
				}
				text, _ := json.Marshal(map[string]any{"scores": scores})
				return map[string]any{"model_version_id": "chat", "invocation_id": fmt.Sprintf("call-%d", calls), "text": string(text)}, nil
			}
			result, err := m.Rerank(context.Background(), m.scope, "定义", chunks)
			want := 1
			if enabled {
				want = 4
			}
			if err != nil || calls != want || total != 25 || len(result.Scores) != 25 {
				t.Fatal(err, calls, total, len(result.Scores))
			}
			if enabled && len(result.InvocationIDs) != 4 {
				t.Fatal("missing billing receipts", result.InvocationIDs)
			}
			for i, score := range result.Scores {
				if score.ChunkID != chunks[i].ID || score.Score != 0.75 {
					t.Fatal("lost canonical identity", score)
				}
			}
		})
	}
}
