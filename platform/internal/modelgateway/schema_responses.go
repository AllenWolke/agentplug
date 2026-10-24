package modelgateway

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/telemetry"
)

// Only an approved schema dialect can select this wire protocol. It shares the
// guarded transport/send observer; it never retries, stores remote sessions or
// executes provider tools. Ordinary chat requests keep their original adapter.
func (a *HTTPAdapter) generateSchemaResponse(ctx context.Context, endpoint string, secret []byte, wireModel string, model ModelMetadata, policy policyasset.ModelPolicy, request GenerateRequest, messages []Message, format *jsonResponseFormat) (GenerateResult, error) {
	if model.ReasoningDialect != "deepseek/v1" && model.ReasoningDialect != "openai-compatible/v1" {
		return GenerateResult{}, ErrModelUnavailable
	}
	input := make([]map[string]string, 0, len(messages))
	for _, m := range messages {
		if len(m.ToolCalls) != 0 || m.ToolCallID != "" || (m.Role != "user" && m.Role != "assistant" && m.Role != "system" && m.Role != "developer") {
			return GenerateResult{}, ErrProviderResponse
		}
		input = append(input, map[string]string{"type": "message", "role": m.Role, "content": m.Content})
	}
	var reasoning map[string]string
	if policy.ReasoningMode != "" || policy.ReasoningEffort != "" {
		effort := policy.ReasoningEffort
		if policy.ReasoningMode == "disabled" {
			effort = "none"
		} else if effort == "" {
			effort = "high"
		}
		reasoning = map[string]string{"effort": effort}
	}
	body, err := json.Marshal(struct {
		Model           string              `json:"model"`
		Input           []map[string]string `json:"input"`
		Temperature     float64             `json:"temperature"`
		MaxOutputTokens int                 `json:"max_output_tokens,omitempty"`
		Reasoning       map[string]string   `json:"reasoning,omitempty"`
		Store           bool                `json:"store"`
		Text            any                 `json:"text"`
	}{wireModel, input, request.Temperature, request.MaxTokens, reasoning, false,
		map[string]any{"format": map[string]any{"type": "json_schema", "name": format.JSONSchema.Name, "strict": true, "schema": format.JSONSchema.Schema}}})
	if err != nil {
		return GenerateResult{}, ErrProviderResponse
	}
	if int64(len(body)) > a.config.MaxRequestBytes {
		return GenerateResult{}, ErrRequestTooLarge
	}
	url, err := endpointURL(endpoint, "responses", a.config)
	if err != nil {
		return GenerateResult{}, err
	}
	raw, err := a.do(ctx, url, secret, body)
	if err != nil {
		return GenerateResult{}, err
	}
	var payload struct {
		Status string `json:"status"`
		Output []struct {
			Type    string          `json:"type"`
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"output"`
		IncompleteDetails struct {
			Reason string `json:"reason"`
		} `json:"incomplete_details"`
		Usage struct {
			Input  *int `json:"input_tokens"`
			Output *int `json:"output_tokens"`
			Detail *struct {
				Cached *int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &payload) != nil || payload.Usage.Input == nil || payload.Usage.Output == nil || *payload.Usage.Input < 0 || *payload.Usage.Output < 0 {
		telemetry.RecordModelProviderResponseInvalid()
		return GenerateResult{}, ErrProviderResponse
	}
	result := GenerateResult{InputTokens: *payload.Usage.Input, OutputTokens: *payload.Usage.Output, ResponseSchema: schemaReceipt(request, model, format)}
	cache := providerCacheUsage{}
	if payload.Usage.Detail != nil {
		cache.Hit = payload.Usage.Detail.Cached
	}
	result.CacheUsage, err = cache.normalize(result.InputTokens)
	if err != nil {
		telemetry.RecordModelContextCacheInvalid()
		return GenerateResult{}, err
	}
	if result.CachedInputTokens == nil {
		telemetry.RecordModelContextCache(0, 0, false)
	} else {
		telemetry.RecordModelContextCache(*result.CachedInputTokens, *result.UncachedInputTokens, true)
	}
	result.Incomplete, result.FinishReason = true, "invalid_response_schema"
	if payload.Status == "incomplete" && payload.IncompleteDetails.Reason == "max_output_tokens" {
		result.FinishReason = "length"
		return result, nil
	}
	if payload.Status != "completed" {
		return result, nil
	}
	var text strings.Builder
	for _, item := range payload.Output {
		if item.Type == "reasoning" {
			continue
		}
		if item.Type != "message" || item.Role != "assistant" || len(item.Content) == 0 {
			return result, nil
		}
		var content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(item.Content, &content) != nil || len(content) == 0 {
			return result, nil
		}
		for _, part := range content {
			if part.Type != "output_text" {
				return result, nil
			}
			text.WriteString(part.Text)
		}
	}
	if !validSchemaResponse(request.ResponseSchema, text.String()) {
		return result, nil
	}
	result.Text, result.Incomplete, result.FinishReason = text.String(), false, "stop"
	return result, nil
}
