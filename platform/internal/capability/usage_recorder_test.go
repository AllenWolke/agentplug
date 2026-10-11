package capability

import (
	"context"
	"testing"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/usagecost"
)

type recordingUsage struct{ events []usagecost.Event }

func (r *recordingUsage) Apply(_ context.Context, event usagecost.Event) (usagecost.Snapshot, error) {
	r.events = append(r.events, event)
	return usagecost.Snapshot{ScopeKey: usagecost.ScopeKey(event.Scope), LastEventID: event.ID}, nil
}

func TestRecordUsageUsesRunScopeAndStableEventID(t *testing.T) {
	recorder := &recordingUsage{}
	module := &Module{usageRecorder: recorder}
	ctx := harnessContext{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1", TaskID: "run-1"}
	result := map[string]any{"model": "local-model", "usage": map[string]int{"input_tokens": 4, "output_tokens": 6}}
	attachModelUsageStepID(result, legacyModelUsageScope(ctx), "call-1")
	pricing := policyasset.ModelPolicy{Provider: "local", InputMicrosPer1KTokens: 10_000_000, OutputMicrosPer1KTokens: 10_000_000}
	if err := module.recordUsage(context.Background(), ctx, pricing, result, "call-1"); err != nil {
		t.Fatal(err)
	}
	if err := module.recordUsage(context.Background(), ctx, pricing, result, "call-1"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.events) != 2 || recorder.events[0].ID != recorder.events[1].ID {
		t.Fatalf("event IDs must be stable: %+v", recorder.events)
	}
	if recorder.events[0].Scope.RunID != "run-1" || recorder.events[0].CostMicros != 100000 || recorder.events[0].StepID == nil || recorder.events[1].StepID == nil || *recorder.events[0].StepID != *recorder.events[1].StepID {
		t.Fatalf("unexpected usage event: %+v", recorder.events[0])
	}
}

func TestRecordUsageDoesNotInventStepIDForLegacyCompletedReceipt(t *testing.T) {
	recorder := &recordingUsage{}
	module := &Module{usageRecorder: recorder}
	ctx := harnessContext{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1", TaskID: "old-run"}
	legacyReceipt := map[string]any{"model": "local-model", "usage": map[string]int{"input_tokens": 4, "output_tokens": 6}}
	if err := module.recordUsage(context.Background(), ctx, policyasset.ModelPolicy{Provider: "local"}, legacyReceipt, "old-call"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.events) != 1 || recorder.events[0].StepID != nil {
		t.Fatalf("legacy completed receipt must not gain a fabricated usage link: %+v", recorder.events)
	}
}

func TestGovernedModelUsageStepIDMatchesResponseStepID(t *testing.T) {
	ctx := harnessContext{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1", TaskID: "run-1"}
	event, err := buildModelUsageEvent(ctx, modelgateway.Selection{ProviderKey: "provider", ModelKey: "model"}, 4, 6, 10, "call-secret")
	if err != nil {
		t.Fatal(err)
	}
	response := make(map[string]any)
	responseStepID := attachModelUsageStepID(response, event.Scope, "call-secret")
	if event.StepID == nil || responseStepID == nil || *event.StepID != *responseStepID || response["step_id"] != *event.StepID {
		t.Fatalf("billing event and stored model response must share a stable step ID: event=%v response=%v map=%v", event.StepID, responseStepID, response)
	}
	if *event.StepID == event.ID || *event.StepID == "call-secret" {
		t.Fatal("step ID must be separate from the existing billing event ID and raw request key")
	}
}

func TestLocalModelUsageIsAttributedToSignedEvaluationParent(t *testing.T) {
	recorder := &recordingUsage{}
	module := &Module{usageRecorder: recorder}
	ctx := harnessContext{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1", TaskID: "case-run", ParentRunID: "evaluation-run"}
	result := map[string]any{"model": "local-model", "usage": map[string]int{"input_tokens": 4, "output_tokens": 6}}
	if err := module.recordUsage(context.Background(), ctx, policyasset.ModelPolicy{Provider: "local"}, result, "case-call"); err != nil {
		t.Fatal(err)
	}
	if len(recorder.events) != 1 || recorder.events[0].Scope.RunID != "evaluation-run" {
		t.Fatalf("local model usage did not preserve signed parent: %+v", recorder.events)
	}
}

func TestPricedModelCostRequiresExternalRatesAndRoundsUp(t *testing.T) {
	if _, err := pricedModelCost(policyasset.ModelPolicy{Provider: "remote", AllowExternal: true}, 1, 1); err == nil {
		t.Fatal("external model without published rates must fail closed")
	}
	cost, err := pricedModelCost(policyasset.ModelPolicy{
		Provider: "remote", AllowExternal: true,
		InputMicrosPer1KTokens: 1001, OutputMicrosPer1KTokens: 2001,
	}, 1, 1)
	if err != nil || cost != 5 { // ceil(1001/1000) + ceil(2001/1000)
		t.Fatalf("priced cost=%d err=%v, want 5", cost, err)
	}
}
