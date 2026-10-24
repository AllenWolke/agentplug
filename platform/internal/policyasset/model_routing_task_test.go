package policyasset

import (
	"encoding/json"
	"strings"
	"testing"
)

func taskRoutingPolicy() ModelRoutingPolicy {
	return ModelRoutingPolicy{Version: "model-routing/v1", ExecutionContextSHA256: strings.Repeat("a", 64), SimpleMaxInputTokens: 256,
		ComplexMinInputTokens: 1024, SimpleMaxOutputTokens: 128, MaxEstimatedMicros: 10000,
		Candidates: []ModelRouteCandidate{
			{QualityEvidenceID: "q-small", ModelVersionID: "small", PriceVersionID: "p-small", CapabilitySHA256: strings.Repeat("b", 64), QualityEvidenceSHA256: strings.Repeat("c", 64), MaxComplexity: "simple"},
			{QualityEvidenceID: "q-large", ModelVersionID: "large", PriceVersionID: "p-large", CapabilitySHA256: strings.Repeat("b", 64), QualityEvidenceSHA256: strings.Repeat("c", 64), MaxComplexity: "complex"}}}
}

func TestRoutingTaskUsesOriginalBusinessDataAndKeepsUnknownComplex(t *testing.T) {
	p := taskRoutingPolicy()
	for _, item := range []struct{ raw, want string }{
		{`{"question":"指标定义是什么"}`, "simple"},
		{`{"question":"完整定义是什么，请保留全部条件"}`, "medium"},
		{`{"question":"what is the complete definition, including all conditions"}`, "medium"},
		{`{"question":"2026-06-30和2026-07-31的定义是什么"}`, "complex"},
		{`{"question":"比较多个口径"}`, "complex"},
		{`{"question":"z987"}`, "complex"},
		{`{"question":"指标定义是什么","policy_snapshot":{"prompt":"比较多个plan"}}`, "simple"},
	} {
		bound, err := BindRoutingTask(ModelSelectionBinding{Selection: ModelSelection{Mode: "automatic"}}, json.RawMessage(item.raw), p)
		if err != nil || bound.TaskComplexity != item.want || !bound.ValidateTask() {
			t.Fatal(item.raw, bound, err)
		}
	}
	base, _ := BindRoutingTask(ModelSelectionBinding{Selection: ModelSelection{Mode: "automatic"}}, json.RawMessage(`{"question":"指标定义是什么"}`), p)
	changed, _ := BindRoutingTask(ModelSelectionBinding{Selection: ModelSelection{Mode: "automatic"}}, json.RawMessage(`{"policy_snapshot":{"secret":"not part of business"},"question":"指标定义是什么"}`), p)
	if base.TaskSHA256 != changed.TaskSHA256 {
		t.Fatal("rendered or supplied policy changed the business task binding")
	}
}

func TestRoutingQualificationContextPinsBehaviorAndAllowsModelComparison(t *testing.T) {
	s := validSnapshot()
	s.Prompt.TemplateHash = "prompt-a"
	before := RoutingExecutionContextSHA256(s)
	s.Model.ModelVersionID, s.Model.Provider, s.Model.Model = "another", "other-api", "other-model"
	s.Model.ReasoningMode = "disabled"
	if RoutingExecutionContextSHA256(s) != before {
		t.Fatal("candidate comparison context contains the selected chat identity")
	}
	s.Prompt.TemplateHash = "prompt-b"
	if RoutingExecutionContextSHA256(s) == before {
		t.Fatal("quality qualification reused across changed Prompt")
	}
	s.Prompt.TemplateHash = "prompt-a"
	s.Runtime.TaskTimeoutSeconds++
	if RoutingExecutionContextSHA256(s) == before {
		t.Fatal("qualification reused with relaxed deadline")
	}
}
