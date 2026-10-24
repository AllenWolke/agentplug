package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func querySchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","minLength":1}},"required":["query"],"additionalProperties":false}`)
}

func TestResponseSchemaPortableBoundsAndLegacyCompatibility(t *testing.T) {
	raw, mode, err := NormalizeResponseSchema(querySchema(), "", true, nil)
	if err != nil || mode != "required" || len(raw) == 0 {
		t.Fatal(err, mode)
	}
	for _, bad := range []string{`null`, `{"type":"array"}`, `{"type":"object","$ref":"https://example.invalid/schema"}`, `{"type":"object","properties":{"q":{"type":"array","items":{"type":"number"},"minItems":null,"maxItems":2}},"required":["q"],"additionalProperties":false}`, strings.Repeat(" ", 16385)} {
		if _, _, err := NormalizeResponseSchema(json.RawMessage(bad), "required", true, nil); err == nil {
			t.Fatal("invalid schema accepted", bad)
		}
	}
	if _, _, err := NormalizeResponseSchema(querySchema(), "unknown", true, nil); err == nil {
		t.Fatal("unknown schema mode accepted")
	}
	if _, _, err := NormalizeResponseSchema(querySchema(), "required", false, nil); err == nil {
		t.Fatal("schema without JSON mode accepted")
	}
	if _, _, err := NormalizeResponseSchema(querySchema(), "required", true, []string{"tool"}); err == nil {
		t.Fatal("schema/function conflict accepted")
	}
	if _, _, err := NormalizeResponseSchema(nil, "", false, nil); err != nil {
		t.Fatal("legacy text changed", err)
	}
	m := approvedModel()
	m.SupportsJSON = true
	r := validRequest()
	r.RequireJSON = true
	r.ResponseSchema = querySchema()
	if _, err := responseFormat(r, m); !errors.Is(err, ErrModelUnavailable) {
		t.Fatal("unsupported required format accepted", err)
	}
	r.ResponseSchemaMode = "prefer_supported"
	f, err := responseFormat(r, m)
	if err != nil || f.Type != "json_object" || f.JSONSchema != nil {
		t.Fatal("compatibility format changed", err)
	}
	legacy := RoutingMetadata{SupportsJSON: true}
	before := legacy.CapabilitySHA256()
	legacy.ResponseSchemaDialect = ResponseSchemaDialect
	if before == legacy.CapabilitySHA256() {
		t.Fatal("schema capability not bound")
	}
}

func TestResponseSchemaActualHTTPAndKnownInvalidUsage(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "other-api-json-mode", true: "approved-schema-api"}[supported], func(t *testing.T) {
			calls := 0
			invalid := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body struct {
					ResponseFormat jsonResponseFormat `json:"response_format"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Fatal("wire decode")
				}
				if supported && (body.ResponseFormat.Type != "json_schema" || body.ResponseFormat.JSONSchema == nil || !body.ResponseFormat.JSONSchema.Strict || !validSchemaResponse(body.ResponseFormat.JSONSchema.Schema, `{"query":"valid"}`)) {
					t.Fatal("approved schema not transmitted")
				}
				if !supported && (body.ResponseFormat.Type != "json_object" || body.ResponseFormat.JSONSchema != nil) {
					t.Fatal("schema sent to unsupported API")
				}
				text := `{"query":"valid"}`
				if invalid {
					text = `{"input":{"query":"invalid"}}`
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": text}}}, "usage": map[string]int{"prompt_tokens": 7, "completion_tokens": 3}})
			}))
			defer server.Close()
			model := approvedModel()
			// Older approved APIs have no JSON capability declaration. Their
			// original json_object behavior must survive optional schema rollout.
			model.SupportsJSON = supported
			if supported {
				model.ResponseSchemaDialect = ResponseSchemaDialect
			}
			adapter := newTestAdapterWithCatalog(t, testCatalog{provider: approvedProvider(server.URL + "/v1"), model: model}, server.URL+"/v1", nil, true)
			r := validRequest()
			r.RequireJSON = true
			r.ResponseSchema = querySchema()
			r.ResponseSchemaMode = "prefer_supported"
			result, err := adapter.Generate(context.Background(), trustedScope(), testSnapshot(), r)
			if err != nil || result.Incomplete || result.ResponseSchema == nil || result.ResponseSchema.SchemaSHA256 == "" || calls != 1 {
				t.Fatal("schema call failed", err, result)
			}
			invalid = true
			result, err = adapter.Generate(context.Background(), trustedScope(), testSnapshot(), r)
			if err != nil || !result.Incomplete || result.Text != "" || result.FinishReason != "invalid_response_schema" || result.InputTokens != 7 || result.OutputTokens != 3 || calls != 2 {
				t.Fatal("invalid response lost known usage or was retried", err, result, calls)
			}
			if !supported {
				r.ResponseSchemaMode = "required"
				_, err = adapter.Generate(context.Background(), trustedScope(), testSnapshot(), r)
				if !errors.Is(err, ErrModelUnavailable) || calls != 2 {
					t.Fatal("unsupported required schema sent", err, calls)
				}
			}
		})
	}
}

func TestResponseSchemaLegacyUndeclaredJSONAndStrictCapability(t *testing.T) {
	m := approvedModel()
	m.SupportsJSON = false
	r := validRequest()
	r.RequireJSON = true
	f, err := responseFormat(r, m)
	if err != nil || f == nil || f.Type != "json_object" {
		t.Fatal("legacy undeclared JSON request changed", err, f)
	}
	r.ResponseSchema = querySchema()
	for _, dialect := range []string{"", ResponseSchemaDialect} {
		m.ResponseSchemaDialect = dialect
		r.ResponseSchemaMode = "required"
		if _, err := responseFormat(r, m); !errors.Is(err, ErrModelUnavailable) {
			t.Fatal("strict schema accepted without approved JSON capability", dialect, err)
		}
	}
}
