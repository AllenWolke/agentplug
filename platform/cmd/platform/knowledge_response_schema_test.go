package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/prompt"
)

func TestKnowledgeSchemaV2UsesAllPassagesAndExactBudgetCallback(t *testing.T) {
	m := stagedKnowledgeFixture(t)
	p, _ := prompt.ParseProgram(m.request.Policy.Prompt.Template)
	p.ExecutionModes = append(p.ExecutionModes, "knowledge-score-vector/v2")
	raw, _ := json.Marshal(p)
	m.request.Policy.Prompt.Template = string(raw)
	checks, calls := 0, 0
	m.request.ModelSchemaInputFits = func(messages []modelgateway.Message, jsonRequired bool, schema json.RawMessage, mode string) bool {
		checks++
		if !jsonRequired || mode != "prefer_supported" || len(schema) == 0 {
			t.Fatal("schema-aware preflight omitted")
		}
		wire, err := prompt.InvocationMessages(m.request.Policy.Prompt.Template, messages)
		return err == nil && capability.ValidateModelContextWithResponseSchema(m.request.Policy.Model, wire, m.request.Policy.Tool, nil, true, schema, mode) == nil
	}
	m.request.ModelCall = func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
		calls++
		s := input["response_schema"].(json.RawMessage)
		var schema struct {
			Properties map[string]struct {
				MinItems int `json:"minItems"`
				MaxItems int `json:"maxItems"`
			} `json:"properties"`
		}
		_ = json.Unmarshal(s, &schema)
		if schema.Properties["scores"].MinItems != 3 || schema.Properties["scores"].MaxItems != 3 {
			t.Fatal("wrong cardinality", string(s))
		}
		return map[string]any{"text": `{"scores":[0.9,0.1,0.2]}`, "model_version_id": "chat", "invocation_id": "schema-call"}, nil
	}
	chunks := []knowledge.HybridChunk{}
	for _, id := range []string{"source-one", "source-two", "source-three"} {
		chunks = append(chunks, knowledge.HybridChunk{Chunk: knowledge.Chunk{ID: id, Text: "complete evidence"}})
	}
	rank, err := m.Rerank(context.Background(), m.scope, "query", chunks)
	if err != nil || calls != 1 || checks != 3 || len(rank.Scores) != 3 {
		t.Fatal(err, calls, checks, rank)
	}
	for i, score := range rank.Scores {
		if score.ChunkID != chunks[i].ID {
			t.Fatal("source identity changed")
		}
	}
	legacy := stagedKnowledgeFixture(t)
	if raw, mode, err := legacy.stageResponseSchema("knowledge.rewrite", nil); err != nil || raw != nil || mode != "" {
		t.Fatal("old release changed", err)
	}
}
