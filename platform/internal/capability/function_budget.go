package capability

import (
	"encoding/json"
	"slices"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

// Include the full tool transcript and schema bytes in conservative input
// admission. Ordinary text requests preserve their existing budget estimate.
func modelBudgetMessages(messages []modelgateway.Message, policy policyasset.ToolPolicy, names []string, requireJSON ...bool) []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
} {
	result := make([]struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}, 0, len(messages)+len(names))
	appendContent := func(role, content string) {
		result = append(result, struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: role, Content: content})
	}
	for _, message := range messages {
		content := message.Content
		if message.ToolCallID != "" || len(message.ToolCalls) > 0 {
			serialized, _ := json.Marshal(message)
			content = string(serialized)
		}
		appendContent(message.Role, content)
	}
	for _, f := range policy.Functions {
		if slices.Contains(names, f.Name) {
			serialized, _ := json.Marshal(f)
			appendContent("tool_definition", string(serialized))
		}
	}
	if len(requireJSON) > 0 && requireJSON[0] {
		appendContent("response_format", `{"type":"json_object"}`)
	}
	return result
}
