package capability

import (
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
)

func TestFunctionBudgetIncludesSchemaCallsAndResults(t *testing.T) {
	base := []modelgateway.Message{{Role: "user", Content: "inspect"}}
	policy := policyasset.ToolPolicy{AllowedTools: []string{"runtime.inspect"}, Functions: []policyasset.FunctionDefinition{{Name: "inspect", ToolName: "runtime.inspect", Parameters: json.RawMessage(`{"type":"object"}`)}}}
	baseline, _ := conservativeInputTokenEstimate(modelBudgetMessages(base, policy, nil))
	withSchema, _ := conservativeInputTokenEstimate(modelBudgetMessages(base, policy, []string{"inspect"}))
	transcript := append(base, modelgateway.Message{Role: "assistant", ToolCalls: []modelgateway.ToolCall{{ID: "call-1", Type: "function", Function: modelgateway.FunctionCall{Name: "inspect", Arguments: `{}`}}}}, modelgateway.Message{Role: "tool", ToolCallID: "call-1", Content: `{"healthy":true}`})
	withRoundTrip, _ := conservativeInputTokenEstimate(modelBudgetMessages(transcript, policy, []string{"inspect"}))
	if baseline != 15 || withSchema <= baseline+int64(len(policy.Functions[0].Parameters)) || withRoundTrip <= withSchema+int64(len(transcript[2].Content)) {
		t.Fatalf("function input budget omitted metadata: baseline=%d schema=%d transcript=%d", baseline, withSchema, withRoundTrip)
	}
}
