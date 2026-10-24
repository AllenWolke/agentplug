package agentplatform

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSharedPublicCapacityAndUnknownMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/fixtures/public-capabilities-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Capacity []struct {
			Name  string
			Reply map[string]any
			Limit uint64
			Error string
		}
		Metadata map[string]any `json:"preserved_model_metadata"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	for _, test := range fixture.Capacity {
		t.Run(test.Name, func(t *testing.T) {
			limit, err := checkpointReplyLimit(test.Reply)
			if test.Error != "" {
				var app *AppError
				if !errors.As(err, &app) || app.Code != test.Error {
					t.Fatalf("expected %s, got %v", test.Error, err)
				}
			} else if err != nil || limit != test.Limit {
				t.Fatalf("limit=%d err=%v", limit, err)
			}
		})
	}
	if !sameRecoveryJSONValue(ModelResultMetadata(fixture.Metadata), fixture.Metadata) {
		t.Fatal("unknown billing or attribution was lost")
	}
}

type publicStateFixture struct {
	harnessFixture
	history            uint64
	denied, lost       bool
	saves, validations int
}

func (f *publicStateFixture) LoadCheckpoint(ctx context.Context, ns, key, schema string, revision uint64) (map[string]any, error) {
	result, err := f.harnessFixture.LoadCheckpoint(ctx, ns, key, schema, revision)
	if f.history != 0 {
		result["checkpoint_history"] = map[string]any{"version": "checkpoint-history/v1", "max_revisions": f.history}
	}
	return result, err
}
func (f *publicStateFixture) SaveCheckpoint(ctx context.Context, ns, key, schema, operation string, rev uint64, state map[string]any) (map[string]any, error) {
	f.saves++
	result, err := f.harnessFixture.SaveCheckpoint(ctx, ns, key, schema, operation, rev, state)
	if f.lost && state["phase"] != "pending" && rev > 0 {
		f.lost = false
		return nil, publicError("STATE_RESULT_UNKNOWN")
	}
	return result, err
}
func (f *publicStateFixture) ValidateCurrentExecution(context.Context) error {
	f.validations++
	if f.denied {
		return publicError("CAPABILITY_DENIED")
	}
	return nil
}
func TestCursorCapacityAdmissionLostAckAndRevocation(t *testing.T) {
	ctx := context.Background()
	f := &publicStateFixture{}
	if _, err := OpenCheckpointCursor(ctx, f, "batch", strings.Repeat("a", 64), 32); err == nil || f.saves != 0 {
		t.Fatal("capacity was not checked before state/effect admission")
	}
	f.history = 4096
	cursor, err := OpenCheckpointCursor(ctx, f, "batch", strings.Repeat("a", 64), 2)
	if err != nil {
		t.Fatal(err)
	}
	if recovering, err := cursor.Begin(ctx); err != nil || recovering {
		t.Fatal(recovering, err)
	}
	f.lost = true
	if err = cursor.Confirm(ctx, strings.Repeat("b", 64)); err == nil || cursor.Index() != 0 {
		t.Fatal("unconfirmed acknowledgement advanced local progress")
	}
	restored, err := OpenCheckpointCursor(ctx, f, "batch", strings.Repeat("a", 64), 2)
	if err != nil || restored.Index() != 1 {
		t.Fatal("confirmed server head was not restored", err)
	}
	if _, err = restored.Begin(ctx); err != nil {
		t.Fatal(err)
	}
	f.denied = true
	if _, err = restored.Begin(ctx); err == nil || f.validations != 1 {
		t.Fatal("pending recovery did not revalidate current authority")
	}
}

type uncertainStep struct {
	fresh, recovered int
	deny             bool
}

func (e *uncertainStep) Execute(context.Context, WorkflowStep, *StepRuntime, map[string]any) (map[string]any, error) {
	e.fresh++
	return nil, publicError("UPSTREAM_TIMEOUT")
}
func (e *uncertainStep) Recover(context.Context, WorkflowStep, *StepRuntime, map[string]any) (map[string]any, error) {
	e.recovered++
	if e.deny {
		return nil, publicError("CAPABILITY_DENIED")
	}
	return map[string]any{"status": "completed", "output": map[string]any{"receipt": "original"}, "covered_slots": []string{"answer"}}, nil
}
func TestStepWorkflowUnknownDispatchNeverExecutesAgain(t *testing.T) {
	ctx := context.Background()
	f := &publicStateFixture{}
	adapter := &uncertainStep{}
	steps := []WorkflowStep{{ID: "answer", Payload: map[string]any{"question": "same"}, DependsOn: []string{}, RequiredSlots: []string{"answer"}}}
	options := DefaultStepWorkflowOptions("workflow", []string{"answer"})
	if _, err := RunStepWorkflow(ctx, f, steps, adapter, options); err == nil {
		t.Fatal("unknown dispatch was declared completed")
	}
	before := f.checkpoint["value"].(map[string]any)["deadline_ms"]
	result, err := RunStepWorkflow(ctx, f, steps, adapter, options)
	if err != nil || result["status"] != "completed" || adapter.fresh != 1 || adapter.recovered != 1 {
		t.Fatalf("result=%v err=%v sends=%d lookups=%d", result, err, adapter.fresh, adapter.recovered)
	}
	if !sameRecoveryJSONValue(before, f.checkpoint["value"].(map[string]any)["deadline_ms"]) {
		t.Fatal("recovery renewed original deadline")
	}
	changed := append([]WorkflowStep(nil), steps...)
	changed[0].Payload = map[string]any{"question": "different"}
	if _, err = RunStepWorkflow(ctx, f, changed, adapter, options); err == nil || adapter.fresh != 1 {
		t.Fatal("changed plan was not rejected")
	}
}

func TestExtendedHarnessHistoryAndNoFreshModelOnReplay(t *testing.T) {
	f := &finishingHarnessFixture{}
	input := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "finish"}}, "function_names": []string{}, "idempotency_key": "same"}
	o := HarnessOptions{Key: "stage", MaxRounds: 1, MaxToolCalls: 1, ExtensionID: "single-model-stage/v1", DeadlineMS: time.Now().Add(time.Minute).UnixMilli()}
	first, err := runHarness(context.Background(), f, input, o)
	if err != nil {
		t.Fatal(err)
	}
	if first.Execution == nil {
		t.Fatal("missing extended attribution")
	}
	models := f.models
	_, err = runHarness(context.Background(), f, input, o)
	if err != nil || f.models != models {
		t.Fatal("completed replay sent a new model", err)
	}
}

type finishingHarnessFixture struct{ harnessFixture }

func (f *finishingHarnessFixture) Post(ctx context.Context, path string, input map[string]any) (map[string]any, error) {
	if path == "/internal/model/generate" {
		f.models++
		return map[string]any{"text": "complete", "usage": map[string]any{"input_tokens": nil}}, nil
	}
	return f.harnessFixture.Post(ctx, path, input)
}

func TestSharedPagedReferenceDigest(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/fixtures/recovery-checkpoint-set-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		References []map[string]any
		Set        struct {
			Count  int
			Digest string
		}
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	digest, err := CheckpointReferenceSetDigest(fixture.References)
	if err != nil || digest != fixture.Set.Digest || len(fixture.References) != fixture.Set.Count {
		t.Fatal("reference metadata digest/escaping changed", digest, err)
	}
}
