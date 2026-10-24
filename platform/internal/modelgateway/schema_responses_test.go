package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func nullableSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"value":{"type":["boolean","null"]}},"required":["value"],"additionalProperties":false}`)
}

func TestNullableSchemaPreservesUnknownAndRejectsUnboundedUnion(t *testing.T) {
	for _, kind := range []string{`["boolean","null"]`, `["null","boolean"]`, `"null"`} {
		raw := json.RawMessage(`{"type":"object","properties":{"value":{"type":` + kind + `}},"required":["value"],"additionalProperties":false}`)
		if _, _, err := NormalizeResponseSchema(raw, "required", true, nil); err != nil || !validSchemaResponse(raw, `{"value":null}`) {
			t.Fatal("nullable value rejected", kind, err)
		}
	}
	for _, value := range []string{`{"value":true}`, `{"value":false}`, `{"value":null}`} {
		if !validSchemaResponse(nullableSchema(), value) {
			t.Fatal("boolean/null changed", value)
		}
	}
	for _, value := range []string{`{}`, `{"value":"false"}`, `{"value":0}`, `{"value":null,"reason_override":null}`} {
		if validSchemaResponse(nullableSchema(), value) {
			t.Fatal("invalid contract accepted", value)
		}
	}
	for _, kind := range []string{`[]`, `["boolean"]`, `["boolean","boolean"]`, `["boolean","string"]`, `["null","null"]`, `["null","no-such-type"]`, `["boolean","null","string"]`} {
		raw := json.RawMessage(`{"type":"object","properties":{"value":{"type":` + kind + `}},"required":["value"],"additionalProperties":false}`)
		if _, _, err := NormalizeResponseSchema(raw, "required", true, nil); err == nil {
			t.Fatal("unsupported union accepted", kind)
		}
	}
}

func TestResponsesSchemaWireKnownUsageAndNoHiddenToolExecution(t *testing.T) {
	for _, scenario := range []string{"valid", "null", "extra-field", "length", "refusal", "tool", "missing-usage", "missing-cache", "invalid-cache", "failed"} {
		t.Run(scenario, func(t *testing.T) {
			catalog := testCatalog{provider: approvedProvider("https://api.deepseek.com/v1"), model: approvedModel()}
			catalog.model.SupportsJSON, catalog.model.ResponseSchemaDialect, catalog.model.ReasoningDialect = true, ResponsesSchemaDialect, "deepseek/v1"
			adapter := newTestAdapterWithCatalog(t, catalog, "https://api.deepseek.com/v1", nil, false)
			calls := 0
			adapter.client.Transport = reasoningWireTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var wire map[string]any
				if json.NewDecoder(r.Body).Decode(&wire) != nil || r.URL.Path != "/v1/responses" || wire["tools"] != nil || wire["response_format"] != nil || wire["max_tokens"] != nil || wire["store"] != false || wire["max_output_tokens"] != float64(100) {
					t.Fatal("incorrect wire protocol", r.URL.Path, wire)
				}
				format := wire["text"].(map[string]any)["format"].(map[string]any)
				if format["strict"] != true || format["type"] != "json_schema" || wire["reasoning"].(map[string]any)["effort"] != "none" {
					t.Fatal("strict schema/reasoning lost", wire)
				}
				encoded, _ := json.Marshal(format["schema"])
				if !validSchemaResponse(encoded, `{"value":null}`) {
					t.Fatal("nullable schema not sent")
				}
				text := `{"value":true}`
				if scenario == "null" {
					text = `{"value":null}`
				}
				if scenario == "extra-field" {
					text = `{"value":true,"reason_override":null}`
				}
				part := map[string]any{"type": "output_text", "text": text}
				item := map[string]any{"type": "message", "role": "assistant", "content": []any{part}}
				if scenario == "refusal" {
					part["type"] = "refusal"
				}
				if scenario == "tool" {
					item["type"] = "function_call"
				}
				usage := map[string]any{"input_tokens": 11, "output_tokens": 5, "input_tokens_details": map[string]any{"cached_tokens": 3}}
				payload := map[string]any{"status": "completed", "output": []any{map[string]any{"type": "reasoning", "content": "private reasoning"}, item}, "usage": usage}
				if scenario == "length" {
					payload["status"] = "incomplete"
					payload["incomplete_details"] = map[string]any{"reason": "max_output_tokens"}
				}
				if scenario == "failed" {
					payload["status"] = "failed"
				}
				if scenario == "missing-usage" {
					delete(payload, "usage")
				}
				if scenario == "missing-cache" {
					delete(usage, "input_tokens_details")
				}
				if scenario == "invalid-cache" {
					usage["input_tokens_details"] = map[string]any{"cached_tokens": 12}
				}
				b, _ := json.Marshal(payload)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b)))}, nil
			})
			request := validRequest()
			request.RequireJSON, request.ResponseSchema, request.ResponseSchemaMode = true, nullableSchema(), "required"
			snapshot := testSnapshot()
			snapshot.Model.ReasoningMode = "disabled"
			result, err := adapter.Generate(context.Background(), trustedScope(), snapshot, request)
			if calls != 1 {
				t.Fatal("request retried or not sent", calls)
			}
			if scenario == "missing-usage" || scenario == "invalid-cache" {
				if !errors.Is(err, ErrProviderResponse) {
					t.Fatal("unknown usage fabricated", err, result)
				}
				return
			}
			if err != nil || result.InputTokens != 11 || result.OutputTokens != 5 || result.ResponseSchema == nil || !result.ResponseSchema.Strict || result.ResponseSchema.WireProtocol != "responses/v1" {
				t.Fatal("receipt/usage lost", err, result)
			}
			valid := scenario == "valid" || scenario == "null" || scenario == "missing-cache"
			if result.Incomplete == valid || valid && result.Text == "" || !valid && result.Text != "" || len(result.ToolCalls) != 0 || strings.Contains(result.Text, "private reasoning") {
				t.Fatal("unsafe output or false completion", result)
			}
			if scenario == "missing-cache" && result.CachedInputTokens != nil {
				t.Fatal("missing cache usage fabricated")
			}
			if scenario != "missing-cache" && (*result.CachedInputTokens != 3 || *result.UncachedInputTokens != 8) {
				t.Fatal("cache usage changed")
			}
			if scenario == "length" && result.FinishReason != "length" {
				t.Fatal("truncation cause lost")
			}
		})
	}
}
