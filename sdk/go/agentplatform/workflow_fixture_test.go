package agentplatform

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type sharedWorkflowExecutor struct {
	sends, recoveries int
	unknown           bool
	budgetExhausted   bool
}

func (e *sharedWorkflowExecutor) Execute(_ context.Context, _ WorkflowStep, r *StepRuntime, _ map[string]any) (map[string]any, error) {
	if e.budgetExhausted {
		if err := r.AdmitCalls([]StepCall{{Kind: "tool", Key: "left"}, {Kind: "tool", Key: "right"}}); err != nil {
			return nil, err
		}
	}
	if err := r.AdmitCall("tool", r.OperationKey); err != nil {
		return nil, err
	}
	e.sends++
	if e.unknown {
		return nil, publicError("UPSTREAM_TIMEOUT")
	}
	return sharedWorkflowReceipt(), nil
}
func (e *sharedWorkflowExecutor) Recover(context.Context, WorkflowStep, *StepRuntime, map[string]any) (map[string]any, error) {
	e.recoveries++
	return sharedWorkflowReceipt(), nil
}
func sharedWorkflowReceipt() map[string]any {
	return map[string]any{"status": "completed", "covered_slots": []string{"answer"}, "output": map[string]any{"receipt": "original"}}
}
func TestSharedWorkflowRecoveryScenarios(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/fixtures/workflow-recovery-public-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Step  WorkflowStep
		Cases []struct {
			Name              string
			Sends, Recoveries int
			Status, Error     string
			FinishReason      string `json:"finish_reason"`
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, test := range fixture.Cases {
		t.Run(test.Name, func(t *testing.T) {
			port, executor := &publicStateFixture{}, &sharedWorkflowExecutor{}
			options := DefaultStepWorkflowOptions("shared", []string{"answer"})
			step := fixture.Step
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.Name == "revoked" {
				port.denied = true
			}
			if test.Name == "timeout" {
				options.DeadlineMS = 1
			}
			if test.Name == "budget_exhausted" {
				options.MaxCalls = map[string]int{"tool": 1}
				executor.budgetExhausted = true
			}
			if test.Name == "cancelled_before_dispatch" {
				cancel()
			}
			executor.unknown = test.Name == "lost_tool_reply" || test.Name == "readonly_pending"
			run := func() (map[string]any, error) {
				return RunStepWorkflow(ctx, port, []WorkflowStep{step}, executor, options)
			}
			result, err := run()
			if executor.unknown {
				var app *AppError
				if !errors.As(err, &app) || app.Code != "UPSTREAM_TIMEOUT" {
					t.Fatalf("lost reply did not retain unknown: %v", err)
				}
				options.InspectOnly = test.Name == "readonly_pending"
				result, err = run()
			}
			if test.Name == "duplicate" || test.Name == "parameter_conflict" {
				if err != nil {
					t.Fatal(err)
				}
				if test.Name == "parameter_conflict" {
					step.Payload = map[string]any{"query": "different"}
				}
				result, err = run()
			}
			if test.Error == "CANCELLED" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if test.Error != "" {
				var app *AppError
				if !errors.As(err, &app) || app.Code != test.Error {
					t.Fatalf("want %s got %v", test.Error, err)
				}
			} else if err != nil || result["status"] != test.Status {
				t.Fatalf("result=%v err=%v", result, err)
			}
			if test.FinishReason != "" && result["finish_reason"] != test.FinishReason {
				t.Fatal(result)
			}
			if executor.sends != test.Sends || executor.recoveries != test.Recoveries {
				t.Fatalf("sends=%d recoveries=%d", executor.sends, executor.recoveries)
			}
		})
	}
}
