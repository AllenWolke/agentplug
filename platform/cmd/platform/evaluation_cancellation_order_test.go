package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/lexagent/platform/internal/execution"
	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestEvaluationCancellationWaitsForActiveStopAndNewestInverse(t *testing.T) {
	children := []execution.BudgetRunFacts{
		{Scope: sharedkernel.Scope{RunID: "new-active"}, Status: platformruntime.StatusRunning},
		{Scope: sharedkernel.Scope{RunID: "completed-new"}, Status: platformruntime.StatusSucceeded},
		{Scope: sharedkernel.Scope{RunID: "completed-old"}, Status: platformruntime.StatusFailed},
	}
	stopped, newestDone := false, false
	var calls []string
	controls := evaluationCaseCancellationControls{
		stop: func(_ context.Context, child execution.BudgetRunFacts) error {
			calls = append(calls, "stop:"+child.Scope.RunID)
			return nil
		},
		stopped: func(_ context.Context, _ execution.BudgetRunFacts) (bool, error) { return stopped, nil },
		compensate: func(_ context.Context, child execution.BudgetRunFacts) error {
			calls = append(calls, "undo:"+child.Scope.RunID)
			return nil
		},
		compensated: func(_ context.Context, child execution.BudgetRunFacts) (bool, error) {
			return child.Scope.RunID != "completed-new" || newestDone, nil
		},
	}
	check := func(expected []string) {
		t.Helper()
		calls = nil
		if err := requestEvaluationCaseCancellation(context.Background(), children, controls); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(calls, expected) {
			t.Fatalf("control order %v, want %v", calls, expected)
		}
	}
	check([]string{"stop:new-active"})
	stopped = true
	children[0].Status = platformruntime.StatusCancelled
	check([]string{"undo:completed-new"})
	newestDone = true
	check([]string{"undo:completed-new", "undo:completed-old"})
}

func TestEvaluationCancellationStopsAllBeforeWaitingAndPreservesControlFailures(t *testing.T) {
	children := []execution.BudgetRunFacts{
		{Scope: sharedkernel.Scope{RunID: "active-a"}, Status: platformruntime.StatusRunning},
		{Scope: sharedkernel.Scope{RunID: "active-b"}, Status: platformruntime.StatusWaiting},
		{Scope: sharedkernel.Scope{RunID: "completed"}, Status: platformruntime.StatusSucceeded},
	}
	var stopped []string
	controls := evaluationCaseCancellationControls{
		stop: func(_ context.Context, child execution.BudgetRunFacts) error {
			stopped = append(stopped, child.Scope.RunID)
			return nil
		},
		stopped: func(context.Context, execution.BudgetRunFacts) (bool, error) { return false, nil },
		compensate: func(context.Context, execution.BudgetRunFacts) error {
			t.Fatal("inverse admitted before active cases were confirmed stopped")
			return nil
		},
		compensated: func(context.Context, execution.BudgetRunFacts) (bool, error) { return true, nil },
	}
	if err := requestEvaluationCaseCancellation(context.Background(), children, controls); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stopped, []string{"active-a", "active-b"}) {
		t.Fatalf("did not stop all cases before waiting: %v", stopped)
	}
	want := errors.New("control receipt unavailable")
	controls.stopped = func(context.Context, execution.BudgetRunFacts) (bool, error) { return false, want }
	if err := requestEvaluationCaseCancellation(context.Background(), children, controls); !errors.Is(err, want) {
		t.Fatalf("stop evidence failure discarded: %v", err)
	}
	controls.stopped = func(context.Context, execution.BudgetRunFacts) (bool, error) { return true, nil }
	controls.compensate = func(context.Context, execution.BudgetRunFacts) error { return want }
	if err := requestEvaluationCaseCancellation(context.Background(), children, controls); !errors.Is(err, want) {
		t.Fatalf("inverse failure discarded: %v", err)
	}
}
