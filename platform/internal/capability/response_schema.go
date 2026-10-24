package capability

import (
	"encoding/json"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

func modelResponseSchemaFingerprint(base string, raw json.RawMessage, mode string) string {
	if len(raw) == 0 {
		return base
	}
	return modelPurposeFingerprint(base, "response_schema/v1:"+mode+":"+string(raw))
}

// Count every schema byte conservatively even if an unsupported provider will
// use the explicitly requested prefer_supported JSON-object compatibility path.
func modelSchemaBudgetMessages(messages []modelgateway.Message, tools policyasset.ToolPolicy, names []string, requireJSON bool, raw json.RawMessage, mode string) []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
} {
	result := modelBudgetMessages(messages, tools, names, requireJSON)
	if len(raw) > 0 {
		body, _ := json.Marshal(map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "agentplug_response", "strict": true, "schema": raw}, "requested_mode": mode})
		result = append(result, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{"response_schema", string(body)})
	}
	return result
}

func ValidateModelContextWithResponseSchema(policy policyasset.ModelPolicy, messages []modelgateway.Message, tools policyasset.ToolPolicy, names []string, requireJSON bool, raw json.RawMessage, mode string) error {
	if policy.ValidateInputLimit() != nil {
		return errContextInvalid
	}
	canonical, effective, err := modelgateway.NormalizeResponseSchema(raw, mode, requireJSON, names)
	if err != nil {
		return errContextInvalid
	}
	estimate := 512
	for _, message := range modelSchemaBudgetMessages(messages, tools, names, requireJSON, canonical, effective) {
		encoded, _ := json.Marshal(message)
		estimate += len(encoded) + 16
	}
	if policy.MaxInputTokens > 0 && estimate > policy.MaxInputTokens {
		return errContextLimit
	}
	return nil
}
