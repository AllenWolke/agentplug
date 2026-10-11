package agentplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type harnessFixture struct {
	modelReceipts    map[string]map[string]any
	modelQueries     int
	failModelSave    bool
	modelStatus      string
	checkpoint       map[string]any
	revision         uint64
	models, effects  int
	unknown          bool
	contexts         int
	contextDenied    bool
	queries          int
	failReceiptSave  bool
	completedReceipt map[string]any
	policyLimits     harnessLoopLimits
	repeatModelTools bool
}

func (f *harnessFixture) LoadCheckpoint(context.Context, string, string, string, uint64) (map[string]any, error) {
	if f.checkpoint == nil {
		return map[string]any{"checkpoint": nil}, nil
	}
	return map[string]any{"checkpoint": f.checkpoint}, nil
}
func (f *harnessFixture) SaveCheckpoint(_ context.Context, _, _, _, _ string, rev uint64, value map[string]any) (map[string]any, error) {
	if f.failModelSave && value["phase"] == "tool" {
		f.failModelSave = false
		return nil, harnessError("STATE_UNAVAILABLE")
	}
	if f.failReceiptSave && value["phase"] == "model" && value["tool_count"] == json.Number("1") {
		f.failReceiptSave = false
		return nil, harnessError("STATE_UNAVAILABLE")
	}
	if rev != f.revision {
		return nil, harnessError("STATE_REVISION_CONFLICT")
	}
	f.revision++
	raw, _ := json.Marshal(value)
	var copy map[string]any
	json.Unmarshal(raw, &copy)
	f.checkpoint = map[string]any{"revision": f.revision, "value": copy}
	return map[string]any{"checkpoint": f.checkpoint}, nil
}
func (f *harnessFixture) Post(_ context.Context, path string, input map[string]any) (map[string]any, error) {
	if path == harnessPolicyPath {
		limits := f.policyLimits
		if limits == (harnessLoopLimits{}) {
			limits = harnessLoopLimits{MaxRounds: 8, MaxToolCalls: 16, MaxRepeatedCalls: 4, MaxElapsedSeconds: 300, LimitBehavior: "error"}
		}
		return map[string]any{
			"version": "harness-policy/v1", "policy_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"server_time_ms": time.Now().UnixMilli(),
			"limits": map[string]any{
				"max_rounds": limits.MaxRounds, "max_tool_calls": limits.MaxToolCalls,
				"max_repeated_calls": limits.MaxRepeatedCalls, "max_elapsed_seconds": limits.MaxElapsedSeconds,
				"limit_behavior": limits.LimitBehavior,
			},
		}, nil
	}
	if path == "/internal/model/receipt" {
		f.modelQueries++
		status := f.modelStatus
		if status == "" {
			status = "completed"
		}
		return map[string]any{"version": "model-receipt/v1", "idempotency_key": input["idempotency_key"], "status": status, "receipt": f.modelReceipts[input["idempotency_key"].(string)]}, nil
	}
	if path == "/internal/tool/receipt" {
		f.queries++
		if input["confirmation_token"] != "opaque" {
			return nil, harnessError("TOOL_CONFIRMATION_REQUIRED")
		}
		status := "completed"
		if f.unknown {
			status = "unknown"
		}
		return map[string]any{"version": "tool-receipt/v1", "tool_name": input["name"], "call_id": input["call_id"], "status": status, "receipt": f.completedReceipt}, nil
	}
	if path == "/internal/context/prepare" {
		f.contexts++
		if f.contextDenied {
			return nil, harnessError("CAPABILITY_DENIED")
		}
		return map[string]any{"messages": append([]any{map[string]any{"role": "system", "content": "approved prompt"}}, input["messages"].([]any)...), "prompt_template_hash": "approved-hash", "source_hash": "source-hash"}, nil
	}
	if path == "/internal/model/generate" {
		messages := input["messages"].([]any)
		if input["prompt_template_hash"] != "approved-hash" || messages[0].(map[string]any)["content"] != "approved prompt" {
			return nil, harnessError("HARNESS_CONTEXT_REJECTED")
		}
		f.models++
		if f.models == 1 || f.repeatModelTools && f.models == 2 {
			arguments := "{}"
			if f.repeatModelTools {
				arguments = `{"ticket":"same"}`
			}
			result := map[string]any{"text": "", "completion_status": "tool_calls", "function_bindings": map[string]any{"change": "ticket.update"}, "tool_calls": []any{map[string]any{"id": fmt.Sprintf("call-%d", f.models), "function": map[string]any{"name": "change", "arguments": arguments}}}}
			if f.modelReceipts == nil {
				f.modelReceipts = map[string]map[string]any{}
			}
			f.modelReceipts[input["idempotency_key"].(string)] = result
			return result, nil
		}
		return map[string]any{"text": "complete"}, nil
	}
	if input["confirmation_token"] != "opaque" {
		return nil, harnessError("TOOL_CONFIRMATION_REQUIRED")
	}
	f.effects++
	if f.unknown {
		return nil, harnessError("TOOL_RESULT_UNKNOWN")
	}
	f.completedReceipt = map[string]any{"observation": map[string]any{"version": "runtime-observation/v1", "tool_name": "ticket.update", "call_id": input["call_id"], "status": "succeeded", "effect": "completed", "instruction_trust": "untrusted_data", "context_output": map[string]any{"ok": true}}}
	return f.completedReceipt, nil
}

func TestHarnessPublishedRepeatedCallLimitStopsBeforeSecondInvocation(t *testing.T) {
	f := &harnessFixture{
		policyLimits:     harnessLoopLimits{MaxRounds: 4, MaxToolCalls: 4, MaxRepeatedCalls: 1, MaxElapsedSeconds: 60, LimitBehavior: "incomplete"},
		repeatModelTools: true,
	}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "resolve"}}, "idempotency_key": "operation"}
	o := HarnessOptions{Key: "loop", MaxRounds: 4, MaxToolCalls: 4, ConfirmationToken: "opaque"}
	result, err := runHarness(context.Background(), f, input, o)
	if err != nil || result.Status != "incomplete" || result.Output["termination_reason"] != "HARNESS_LIMIT_EXCEEDED" || result.Output["finish_reason"] != "repeated_tool_limit" {
		t.Fatal(result, err)
	}
	if f.effects != 1 || f.models != 2 {
		t.Fatal("repeated call was dispatched or model loop continued", f.effects, f.models)
	}
}
func TestHarnessApprovalPauseRestoresAndDoesNotRepeatCompletedEffects(t *testing.T) {
	f := &harnessFixture{}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "resolve ticket"}}, "idempotency_key": "operation"}
	o := HarnessOptions{Key: "loop", MaxRounds: 3, MaxToolCalls: 4}
	result, err := runHarness(context.Background(), f, input, o)
	if err != nil || result.Status != "approval_required" || result.Pending == nil || f.models != 1 || f.effects != 0 {
		t.Fatal(result, err)
	}
	callID := result.Pending.CallID
	result, err = runHarness(context.Background(), f, input, o)
	if err != nil || result.Pending.CallID != callID || f.models != 1 {
		t.Fatal("pending approval was regenerated", err)
	}
	o.ConfirmationToken = "opaque"
	result, err = runHarness(context.Background(), f, input, o)
	if err != nil || result.Status != "completed" || f.models != 2 || f.effects != 1 || f.contexts != 2 {
		t.Fatal(result, err)
	}
	result, err = runHarness(context.Background(), f, input, o)
	if err != nil || result.Status != "completed" || f.models != 2 || f.effects != 1 {
		t.Fatal("completed effect repeated", err)
	}
	raw, _ := json.Marshal(f.checkpoint)
	if string(raw) == "" {
		t.Fatal("no checkpoint")
	}
	input["idempotency_key"] = "changed"
	if _, err = runHarness(context.Background(), f, input, o); err == nil {
		t.Fatal("changed initial operation accepted")
	}
}

func TestHarnessContextDenialOccursBeforeModelOrCheckpointDispatch(t *testing.T) {
	f := &harnessFixture{contextDenied: true}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "question"}}, "idempotency_key": "operation"}
	if _, err := runHarness(context.Background(), f, input, HarnessOptions{Key: "loop", MaxRounds: 3, MaxToolCalls: 4}); err == nil {
		t.Fatal("denied context accepted")
	}
	if f.models != 0 || f.effects != 0 || f.revision != 0 {
		t.Fatal("context denial dispatched a model or changed durable state")
	}
}
func TestHarnessUnknownEffectStopsRecoveryWithoutAutomaticRedispatch(t *testing.T) {
	f := &harnessFixture{unknown: true}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "resolve"}}, "idempotency_key": "operation"}
	o := HarnessOptions{Key: "loop", MaxRounds: 3, MaxToolCalls: 4, ConfirmationToken: "opaque"}
	if _, err := runHarness(context.Background(), f, input, o); err == nil {
		t.Fatal("unknown effect accepted")
	}
	if _, err := runHarness(context.Background(), f, input, o); err == nil {
		t.Fatal("uncertain dispatch recovered without reconciliation")
	}
	if f.effects != 1 || f.models != 1 {
		t.Fatal("effect or model repeated")
	}
}

func TestHarnessRecoversCommittedReceiptAfterCheckpointWriteFailure(t *testing.T) {
	f := &harnessFixture{failReceiptSave: true}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "resolve"}}, "idempotency_key": "operation"}
	o := HarnessOptions{Key: "loop", MaxRounds: 3, MaxToolCalls: 4, ConfirmationToken: "opaque"}
	if _, err := runHarness(context.Background(), f, input, o); err == nil {
		t.Fatal("write failure ignored")
	}
	o.ConfirmationToken = ""
	if result, err := runHarness(context.Background(), f, input, o); err != nil || result.Status != "approval_required" || f.effects != 1 {
		t.Fatal("read bypassed approval or repeated effect", err)
	}
	if f.checkpoint["value"].(map[string]any)["phase"] != "tool_dispatch" {
		t.Fatal("receipt approval pause erased the persisted dispatch boundary")
	}
	o.ConfirmationToken = "opaque"
	result, err := runHarness(context.Background(), f, input, o)
	if err != nil || result.Status != "completed" || f.effects != 1 || f.models != 2 || f.queries != 2 {
		t.Fatal("receipt recovery failed or redispatched", result, err, "effects", f.effects, "models", f.models, "queries", f.queries)
	}
}

func TestHarnessModelReceiptRecoveryDoesNotRepeatDispatchOrContext(t *testing.T) {
	for _, status := range []string{"completed", "not_found", "running", "failed", "reconcile"} {
		t.Run(status, func(t *testing.T) {
			f := &harnessFixture{failModelSave: true, modelStatus: status}
			input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "resolve"}}, "idempotency_key": "operation"}
			o := HarnessOptions{Key: "loop", MaxRounds: 3, MaxToolCalls: 4, ConfirmationToken: "opaque"}
			if _, err := runHarness(context.Background(), f, input, o); err == nil {
				t.Fatal("checkpoint failure ignored")
			}
			result, err := runHarness(context.Background(), f, input, o)
			if status == "completed" {
				if err != nil || result.Status != "completed" || f.models != 2 || f.contexts != 2 || f.effects != 1 {
					t.Fatal(result, err, f.models, f.contexts, f.effects)
				}
			} else if err == nil || f.models != 1 || f.contexts != 1 || f.effects != 0 {
				t.Fatal("unknown model redispatched", err)
			}
			if f.modelQueries != 1 {
				t.Fatal("missing read-only query")
			}
		})
	}
}
