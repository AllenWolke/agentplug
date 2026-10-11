package service

import (
	"context"
	"errors"
	"github.com/lexagent/agent-platform-sdk-go/agentplatform"
	"strings"
	"testing"
)

func TestJudgeExplicitEvidenceIDsRejectsNestedReferences(t *testing.T) {
	p := &scriptedPort{handle: func(path string, in map[string]any) (map[string]any, error) {
		if path == "/internal/context/prepare" {
			messages := in["messages"].([]map[string]any)
			text := messages[0]["content"].(string)
			if !strings.Contains(text, `Allowed evidence IDs are ONLY these top-level keys: ["output"]`) || !strings.Contains(text, "Nested answer IDs") || !strings.Contains(text, `["output","expected"]`) {
				t.Fatal("missing explicit evidence protocol")
			}
			return map[string]any{"messages": []any{"prepared"}, "prompt_template_hash": "hash"}, nil
		}
		return map[string]any{"text": `{"verdicts":[{"metric_id":"faithfulness","value":true,"evidence":["answer-1"],"reason":"A nested answer ID is not an authorized evidence key"}]}`}, nil
	}}
	out, err := runJudge(context.Background(), judgeRequest(), p)
	var app *agentplatform.AppError
	if out != nil || !errors.As(err, &app) || app.Code != "JUDGE_MODEL_RESPONSE_INVALID" {
		t.Fatal("invented evidence was scored or failure classification lost")
	}
}
