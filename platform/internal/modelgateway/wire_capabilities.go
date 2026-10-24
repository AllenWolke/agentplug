package modelgateway

import (
	"encoding/json"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
)

// Reviewed definition capabilities describe the provider wire dialect and model
// alias. They never contain endpoints or credentials and are not Agent inputs.
type WireCapabilities struct {
	ResponseSchemaDialect string `json:"response_schema_dialect,omitempty"`
	ContextCacheMode      string `json:"context_cache_mode,omitempty"`
	Protocol              string `json:"provider_protocol"`
	ReasoningDialect      string `json:"reasoning_dialect"`
	WireModel             string `json:"wire_model"`
}

func qwenThinkingSwitch(model ModelMetadata, policy policyasset.ModelPolicy) *bool {
	if model.ReasoningDialect != "qwen/v1" || policy.ReasoningMode == "" {
		return nil
	}
	enabled := policy.ReasoningMode == "enabled"
	return &enabled
}

func ParseWireCapabilities(raw json.RawMessage) (WireCapabilities, error) {
	var c WireCapabilities
	if json.Unmarshal(raw, &c) != nil || (c.ResponseSchemaDialect != "" && !SupportsResponseSchema(c.ResponseSchemaDialect)) || (c.ContextCacheMode != "" && c.ContextCacheMode != "provider_prefix") || (c.Protocol != "" && c.Protocol != "openai-compatible/v1") ||
		(c.ReasoningDialect != "" && c.ReasoningDialect != "deepseek/v1" && c.ReasoningDialect != "ollama/v1" && c.ReasoningDialect != "openai-compatible/v1" && c.ReasoningDialect != "qwen/v1") ||
		len(c.WireModel) > 128 || strings.TrimSpace(c.WireModel) != c.WireModel || strings.Contains(c.WireModel, "://") {
		return WireCapabilities{}, ErrModelUnavailable
	}
	for _, r := range c.WireModel {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/", r)) {
			return WireCapabilities{}, ErrModelUnavailable
		}
	}
	return c, nil
}

func ValidateWireReasoning(dialect, mode, effort string) error {
	if (policyasset.ModelPolicy{ReasoningMode: mode, ReasoningEffort: effort}).ValidateReasoningMode() != nil {
		return ErrModelUnavailable
	}
	switch dialect {
	case "", "deepseek/v1":
		return nil // Legacy endpoint validation happens before send.
	case "ollama/v1":
		if effort != "" && effort != "high" {
			return ErrModelUnavailable
		}
	case "qwen/v1":
		// This reviewed dialect uses the documented enable_thinking boolean.
		// Unsupported effort aliases must not be silently dropped.
		if effort != "" {
			return ErrModelUnavailable
		}
	case "openai-compatible/v1":
		// A generic chat API has no standard explicit disable switch.
		if mode == "disabled" || mode == "enabled" && effort == "" {
			return ErrModelUnavailable
		}
	default:
		return ErrModelUnavailable
	}
	return nil
}

func publishedWireReasoning(endpoint string, model ModelMetadata, policy policyasset.ModelPolicy) (*thinkingMode, string, error) {
	if ValidateWireReasoning(model.ReasoningDialect, policy.ReasoningMode, policy.ReasoningEffort) != nil {
		return nil, "", ErrModelUnavailable
	}
	switch model.ReasoningDialect {
	case "":
		thinking, err := publishedThinkingMode(endpoint, policy.ReasoningMode)
		return thinking, policy.ReasoningEffort, err
	case "deepseek/v1":
		if policy.ReasoningMode == "" {
			return nil, policy.ReasoningEffort, nil
		}
		return &thinkingMode{Type: policy.ReasoningMode}, policy.ReasoningEffort, nil
	case "ollama/v1":
		if policy.ReasoningMode == "disabled" {
			return nil, "none", nil
		}
		if policy.ReasoningMode == "enabled" {
			return nil, "high", nil
		}
		return nil, "", nil
	case "openai-compatible/v1":
		return nil, policy.ReasoningEffort, nil
	case "qwen/v1":
		return nil, "", nil
	default:
		return nil, "", ErrModelUnavailable
	}
}
