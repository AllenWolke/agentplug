package modelgateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReviewedQwenThinkingModeUsesBooleanWithoutDeepSeekFields(t *testing.T) {
	for _, mode := range []string{"", "disabled", "enabled"} {
		t.Run(mode, func(t *testing.T) {
			catalog := testCatalog{provider: approvedProvider("https://qwen.example/v1"), model: approvedModel()}
			catalog.model.ReasoningDialect = "qwen/v1"
			adapter := newTestAdapterWithCatalog(t, catalog, "https://qwen.example/v1", nil, false)
			calls := 0
			adapter.client.Transport = reasoningWireTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Fatal("invalid request")
				}
				value, present := body["enable_thinking"]
				if mode == "" && present || mode != "" && (!present || value != (mode == "enabled")) {
					t.Fatal("Qwen thinking mode not faithfully serialized", body)
				}
				if body["thinking"] != nil || body["reasoning_effort"] != nil {
					t.Fatal("vendor dialects mixed")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"choices":[{"finish_reason":"stop","message":{"content":"OK"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`))}, nil
			})
			snapshot := testSnapshot()
			snapshot.Model.ReasoningMode = mode
			if _, err := adapter.Generate(context.Background(), trustedScope(), snapshot, validRequest()); err != nil || calls != 1 {
				t.Fatal("reviewed Qwen mode failed", err)
			}
			snapshot.Model.ReasoningMode, snapshot.Model.ReasoningEffort = "enabled", "max"
			if _, err := adapter.Generate(context.Background(), trustedScope(), snapshot, validRequest()); err == nil || calls != 1 {
				t.Fatal("unsupported effort silently dropped or sent")
			}
		})
	}
}
