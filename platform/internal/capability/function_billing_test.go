package capability

import (
	"encoding/json"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestFunctionResultSettlesAndReplaysExactlyOnce(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid function", true: "invalid provider function"}[invalid], func(t *testing.T) {
			policy := governedInvocationResolver()
			policy.snapshot.Tool = policyasset.ToolPolicy{AllowedTools: []string{"runtime.inspect", "clock.now"}, Functions: []policyasset.FunctionDefinition{
				{Name: "inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object"}`)},
				{Name: "clock", ToolName: "clock.now", Parameters: json.RawMessage(`{"type":"object"}`)},
			}}
			result := modelgateway.GenerateResult{InputTokens: 17, OutputTokens: 9, FinishReason: "tool_calls", ToolCalls: []modelgateway.ToolCall{{ID: "call-1", Type: "function", Function: modelgateway.FunctionCall{Name: "inspect", Arguments: `{}`}}}}
			if invalid {
				result.ToolCalls = nil
				result.Incomplete = true
				result.FinishReason = "invalid_tool_calls"
			}
			gateway := &captureModelGateway{result: result}
			budget := &captureModelBudgetStore{}
			module := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, policy)
			module.SetGovernedModelInvocation(fixedModelAccess(), gateway)
			module.SetModelBilling(testApprovedPriceResolver(), budget)
			module.SetModelCapacity(&captureModelCapacity{})
			input := map[string]any{"idempotency_key": "native-function", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "inspect"}}, "function_names": []string{"inspect"}}
			response := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
			expectedStatus := http.StatusOK
			if invalid {
				expectedStatus = http.StatusBadGateway
			}
			if response.Code != expectedStatus || gateway.calls != 1 || budget.settleCalls != 1 || len(budget.settled) != 1 || budget.settled[0].InputTokens != 17 || budget.settled[0].OutputTokens != 9 {
				t.Fatalf("function usage was not settled: status=%d calls=%d settles=%d body=%s", response.Code, gateway.calls, budget.settleCalls, response.Body.String())
			}
			if invalid {
				if budget.settled[0].StepID == nil ||
					!strings.Contains(response.Body.String(), `"error_code":"MODEL_FUNCTION_INVALID"`) ||
					!strings.Contains(response.Body.String(), `"step_id":"`+*budget.settled[0].StepID+`"`) ||
					strings.Contains(response.Body.String(), `"tool_calls"`) {
					t.Fatal("invalid function was disclosed or misclassified")
				}
			} else if !strings.Contains(response.Body.String(), `"function_bindings":{"inspect":"runtime.inspect"}`) {
				t.Fatal("published tool binding missing")
			}
			replayed := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
			var firstJSON, replayJSON any
			_ = json.Unmarshal(response.Body.Bytes(), &firstJSON)
			_ = json.Unmarshal(replayed.Body.Bytes(), &replayJSON)
			if replayed.Code != expectedStatus || gateway.calls != 1 || budget.settleCalls != 1 || !reflect.DeepEqual(firstJSON, replayJSON) {
				t.Fatal("native result replay repeated provider charge")
			}
			input["function_names"] = []string{"inspect", "clock"}
			conflict := capabilityRequest(t, module, "/internal/model/generate", capabilityContext(), input)
			if conflict.Code != http.StatusConflict || gateway.calls != 1 {
				t.Fatal("different function selection replayed same invocation")
			}
		})
	}
}
