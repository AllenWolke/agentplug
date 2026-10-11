package modelgateway

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/lexagent/platform/internal/policyasset"
)

type wireTool struct {
	Type     string       `json:"type"`
	Function wireFunction `json:"function"`
}
type wireFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ValidateFunctionRequest validates published definitions and the complete
// transcript before budget reservation or any provider request is sent.
func ValidateFunctionRequest(policy policyasset.ToolPolicy, names []string, messages []Message) error {
	_, err := prepareFunctions(policy, names, messages)
	return err
}

func prepareFunctions(policy policyasset.ToolPolicy, names []string, messages []Message) ([]wireTool, error) {
	if policy.ValidateFunctions() != nil || len(names) > 32 {
		return nil, policyasset.ErrFunctionDenied
	}
	tools := make([]wireTool, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			return nil, policyasset.ErrFunctionDenied
		}
		seen[name] = true
		found := false
		for _, f := range policy.Functions {
			if f.Name == name {
				tools = append(tools, wireTool{Type: "function", Function: wireFunction{Name: f.Name, Description: f.Description, Parameters: f.Parameters}})
				found = true
				break
			}
		}
		if !found {
			return nil, policyasset.ErrFunctionDenied
		}
	}
	// Every tool result must consume a unique preceding, validated assistant
	// call. User/system messages cannot forge tool results or tool identities.
	pending, used := map[string]bool{}, map[string]bool{}
	for _, message := range messages {
		if len(pending) > 0 && message.Role != "tool" {
			return nil, policyasset.ErrFunctionDenied
		}
		if message.Role == "tool" {
			if !pending[message.ToolCallID] || len(message.ToolCalls) != 0 {
				return nil, policyasset.ErrFunctionDenied
			}
			delete(pending, message.ToolCallID)
			continue
		}
		if message.Role != "system" && message.Role != "user" && message.Role != "assistant" || message.ToolCallID != "" {
			return nil, policyasset.ErrFunctionDenied
		}
		if len(message.ToolCalls) > 0 {
			if message.Role != "assistant" || validateToolCalls(policy, names, message.ToolCalls) != nil {
				return nil, policyasset.ErrFunctionDenied
			}
			for _, call := range message.ToolCalls {
				if used[call.ID] {
					return nil, policyasset.ErrFunctionDenied
				}
				used[call.ID], pending[call.ID] = true, true
			}
		}
	}
	if len(pending) != 0 {
		return nil, policyasset.ErrFunctionDenied
	}
	return tools, nil
}

func validateToolCalls(policy policyasset.ToolPolicy, names []string, calls []ToolCall) error {
	if len(calls) > 32 {
		return policyasset.ErrFunctionDenied
	}
	seen := map[string]bool{}
	for _, call := range calls {
		if strings.TrimSpace(call.ID) != call.ID || call.ID == "" || len(call.ID) > 128 || seen[call.ID] || call.Type != "function" || !slices.Contains(names, call.Function.Name) {
			return policyasset.ErrFunctionDenied
		}
		seen[call.ID] = true
		if _, err := policy.ValidateFunctionArguments(call.Function.Name, json.RawMessage(call.Function.Arguments)); err != nil {
			return err
		}
	}
	return nil
}

func reusedResponseCallID(messages []Message, calls []ToolCall) bool {
	seen := map[string]bool{}
	for _, message := range messages {
		for _, call := range message.ToolCalls {
			seen[call.ID] = true
		}
	}
	for _, call := range calls {
		if seen[call.ID] {
			return true
		}
	}
	return false
}
