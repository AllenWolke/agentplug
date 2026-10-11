package policyasset

import (
	"encoding/json"
	"testing"
)

func TestPublishedFunctionsRejectUnapprovedToolsAndRemoteSchema(t *testing.T) {
	for name, policy := range map[string]ToolPolicy{
		"empty allowlist":   {Functions: []FunctionDefinition{{Name: "inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object"}`)}}},
		"remote schema":     {AllowedTools: []string{"runtime.inspect"}, Functions: []FunctionDefinition{{Name: "inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object","properties":{"value":{"$ref":"https://example.com/private-schema"}}}`)}}},
		"invalid wire name": {AllowedTools: []string{"runtime.inspect"}, Functions: []FunctionDefinition{{Name: "runtime.inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object"}`)}}},
	} {
		t.Run(name, func(t *testing.T) {
			if policy.ValidateFunctions() == nil {
				t.Fatal("unsafe published function accepted")
			}
		})
	}
}
