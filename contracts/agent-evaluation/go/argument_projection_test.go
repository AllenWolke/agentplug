package agenteval

import "testing"

func TestProtectedArgumentMaskIsUnknownAndUnmaskedMismatchIsWrong(t *testing.T) {
	v := trial()
	v.Expected.Tools = &ToolRules{Parameters: map[string]map[string]any{"read": {"batch_id": "batch"}}}
	v.Trajectory.Events = []Event{{Kind: "tool", ToolName: "read", StepID: "one", Status: "succeeded", Arguments: map[string]any{"batch_id": "[REDACTED]"}}}
	if metric(t, Score([]Trial{v}), "tool_parameter_accuracy").Value != nil {
		t.Fatal("masked input was graded as wrong or correct")
	}
	v.Trajectory.Events[0].Arguments = map[string]any{"batch_id": "other", "password": "[REDACTED]"}
	m := metric(t, Score([]Trial{v}), "tool_parameter_accuracy")
	if m.Value == nil || *m.Value != 0 {
		t.Fatal("known wrong required parameter became unknown")
	}
	v.Trajectory.Events[0].Arguments["batch_id"] = "batch"
	m = metric(t, Score([]Trial{v}), "tool_parameter_accuracy")
	if m.Value == nil || *m.Value != 1 {
		t.Fatal("unrelated redaction erased required parameter evidence")
	}
}
