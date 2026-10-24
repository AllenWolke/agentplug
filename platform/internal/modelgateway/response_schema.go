package modelgateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"

	"github.com/google/jsonschema-go/jsonschema"
)

const ResponseSchemaDialect = "json-schema/openai/v1"
const ResponsesSchemaDialect = "json-schema/responses/v1"

// SupportsResponseSchema is shared by admission, routing and the wire adapter.
// Approval of a dialect is explicit; JSON-object support does not imply it.
func SupportsResponseSchema(dialect string) bool {
	return dialect == ResponseSchemaDialect || dialect == ResponsesSchemaDialect
}

// NormalizeResponseSchema reuses the platform's schema compiler. A bounded
// portable subset excludes references and executable/remote schema loaders.
// Nil preserves all legacy request identities and JSON-object behavior.
func NormalizeResponseSchema(raw json.RawMessage, mode string, requireJSON bool, functions []string) (json.RawMessage, string, error) {
	if len(raw) == 0 {
		if mode != "" {
			return nil, "", ErrProviderResponse
		}
		return nil, "", nil
	}
	if !requireJSON || len(functions) != 0 || len(raw) > 16384 {
		return nil, "", ErrProviderResponse
	}
	if mode == "" {
		mode = "required"
	}
	if mode != "required" && mode != "prefer_supported" {
		return nil, "", ErrProviderResponse
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil || object["type"] != "object" {
		return nil, "", ErrProviderResponse
	}
	nodes := 0
	if !boundedResponseSchema(object, 0, &nodes) {
		return nil, "", ErrProviderResponse
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, "", ErrProviderResponse
	}
	var schema jsonschema.Schema
	if json.Unmarshal(canonical, &schema) != nil {
		return nil, "", ErrProviderResponse
	}
	if _, err := schema.Resolve(&jsonschema.ResolveOptions{}); err != nil {
		return nil, "", ErrProviderResponse
	}
	return canonical, mode, nil
}

func boundedResponseSchema(s map[string]any, depth int, nodes *int) bool {
	*nodes++
	if depth > 6 || *nodes > 128 {
		return false
	}
	allowed := map[string]bool{"type": true, "properties": true, "required": true, "additionalProperties": true,
		"items": true, "minItems": true, "maxItems": true, "minimum": true, "maximum": true,
		"minLength": true, "maxLength": true, "enum": true}
	for k := range s {
		if !allowed[k] {
			return false
		}
	}
	kind, ok := s["type"].(string)
	if !ok {
		// A bounded nullable union, not arbitrary polymorphism. Preserve null as
		// unknown rather than forcing callers to invent a boolean or sentinel.
		types, valid := s["type"].([]any)
		if !valid || len(types) != 2 {
			return false
		}
		a, aok := types[0].(string)
		b, bok := types[1].(string)
		if !aok || !bok || a == b || a != "null" && b != "null" {
			return false
		}
		kind = a
		if kind == "null" {
			kind = b
		}
	}
	switch kind {
	case "object":
		p, ok := s["properties"].(map[string]any)
		r, rok := s["required"].([]any)
		if !ok || !rok || len(p) == 0 || len(p) > 32 || len(r) != len(p) || s["additionalProperties"] != false {
			return false
		}
		seen := map[string]bool{}
		for _, field := range r {
			name, ok := field.(string)
			if !ok || name == "" || len(name) > 64 || seen[name] {
				return false
			}
			child, ok := p[name].(map[string]any)
			if !ok || !boundedResponseSchema(child, depth+1, nodes) {
				return false
			}
			seen[name] = true
		}
	case "array":
		child, ok := s["items"].(map[string]any)
		if !ok || !boundedResponseSchema(child, depth+1, nodes) {
			return false
		}
	case "string", "number", "integer", "boolean", "null":
	default:
		return false
	}
	for _, pair := range [][3]string{{"minItems", "maxItems", "1024"}, {"minLength", "maxLength", "65536"}, {"minimum", "maximum", ""}} {
		low, hasLow := s[pair[0]]
		high, hasHigh := s[pair[1]]
		if hasLow && low == nil || hasHigh && high == nil {
			return false
		}
		for _, value := range []any{low, high} {
			if value == nil {
				continue
			}
			n, ok := value.(float64)
			if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
				return false
			}
			if pair[2] != "" && (n < 0 || n != math.Trunc(n) || pair[2] == "1024" && n > 1024 || pair[2] == "65536" && n > 65536) {
				return false
			}
		}
		if hasLow && hasHigh && low.(float64) > high.(float64) {
			return false
		}
	}
	if values, exists := s["enum"]; exists {
		items, ok := values.([]any)
		if !ok || len(items) == 0 || len(items) > 64 {
			return false
		}
		for _, item := range items {
			switch item.(type) {
			case string, float64, bool, nil:
			default:
				return false
			}
		}
	}
	return true
}

func responseFormat(request GenerateRequest, model ModelMetadata) (*jsonResponseFormat, error) {
	raw, mode, err := NormalizeResponseSchema(request.ResponseSchema, request.ResponseSchemaMode, request.RequireJSON, request.FunctionNames)
	if err != nil {
		return nil, err
	}
	if !request.RequireJSON {
		return nil, nil
	}
	// Legacy JSON-object requests predate capability declarations. Optional
	// schemas preserve that wire contract when no schema dialect is published;
	// strict schema requests still require both approved capabilities below.
	if len(raw) == 0 || model.ResponseSchemaDialect == "" && mode == "prefer_supported" {
		return &jsonResponseFormat{Type: "json_object"}, nil
	}
	if !model.SupportsJSON || !SupportsResponseSchema(model.ResponseSchemaDialect) {
		return nil, ErrModelUnavailable
	}
	return &jsonResponseFormat{Type: "json_schema", JSONSchema: &wireResponseSchema{Name: "agentplug_response", Strict: true, Schema: raw}}, nil
}

type wireResponseSchema struct {
	Name   string          `json:"name"`
	Strict bool            `json:"strict"`
	Schema json.RawMessage `json:"schema"`
}

func schemaReceipt(request GenerateRequest, model ModelMetadata, applied *jsonResponseFormat) *ResponseSchemaReceipt {
	if len(request.ResponseSchema) == 0 {
		return nil
	}
	raw, mode, err := NormalizeResponseSchema(request.ResponseSchema, request.ResponseSchemaMode, request.RequireJSON, request.FunctionNames)
	if err != nil || applied == nil {
		return nil
	}
	protocol := "chat-completions/v1"
	if applied.Type == "json_schema" && model.ResponseSchemaDialect == ResponsesSchemaDialect {
		protocol = "responses/v1"
	}
	return &ResponseSchemaReceipt{Version: "model-response-schema/v1", RequestedMode: mode, AppliedFormat: applied.Type, Dialect: model.ResponseSchemaDialect, SchemaSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), WireProtocol: protocol, Strict: applied.Type == "json_schema"}
}

func validSchemaResponse(raw json.RawMessage, text string) bool {
	if len(raw) == 0 {
		return true
	}
	var schema jsonschema.Schema
	if json.Unmarshal(raw, &schema) != nil {
		return false
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{})
	var value any
	return err == nil && json.Unmarshal([]byte(text), &value) == nil && resolved.Validate(value) == nil
}
