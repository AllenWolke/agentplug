package main

import (
	"encoding/json"

	"github.com/lexagent/platform/internal/knowledge"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/prompt"
)

// Immutable v2 publications opt into schema hints; old waiting workflows keep
// their original JSON-object protocol, fingerprints, and model receipts.
func (m knowledgeQueryModels) stageResponseSchema(stage string, messages []modelgateway.Message) (json.RawMessage, string, error) {
	p, err := prompt.ParseProgram(m.request.Policy.Prompt.Template)
	if err != nil {
		return nil, "", err
	}
	if !p.HasMode("knowledge-score-vector/v2") && !p.HasMode("knowledge-score-vector/v3") && !p.HasMode("knowledge-score-vector/v4") {
		return nil, "", nil
	}
	var field string
	var value map[string]any
	switch stage {
	case "knowledge.rewrite":
		field = "query"
		value = map[string]any{"type": "string", "minLength": 1, "maxLength": 16384}
	case "knowledge.rerank":
		var envelope struct {
			Stage string `json:"stage"`
			Input struct {
				Passages []json.RawMessage `json:"passages"`
			} `json:"input"`
		}
		found := false
		for _, message := range messages {
			if message.Role == "user" && json.Unmarshal([]byte(message.Content), &envelope) == nil && envelope.Stage == stage {
				found = true
			}
		}
		n := len(envelope.Input.Passages)
		if !found || n < 1 || n > 100 {
			return nil, "", knowledge.ErrInvalidQueryStage
		}
		field = "scores"
		value = map[string]any{"type": "array", "items": map[string]any{"type": "number", "minimum": 0, "maximum": 1}, "minItems": n, "maxItems": n}
	default:
		return nil, "", nil
	}
	raw, err := json.Marshal(map[string]any{"type": "object", "properties": map[string]any{field: value}, "required": []string{field}, "additionalProperties": false})
	if err != nil {
		return nil, "", err
	}
	return modelgateway.NormalizeResponseSchema(raw, "prefer_supported", true, nil)
}
