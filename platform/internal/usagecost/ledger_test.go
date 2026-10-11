package usagecost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testUsageScope() Scope {
	return Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1", RunID: "run"}
}

func TestStableModelUsageStepIDBindsScopeAndRequestWithoutPersistingRequest(t *testing.T) {
	scope := testUsageScope()
	first := StableModelUsageStepID(scope, "request-secret-fixture")
	replay := StableModelUsageStepID(scope, "request-secret-fixture")
	if first == nil || replay == nil || *first != *replay || len(*first) != len("model-step-")+64 {
		t.Fatalf("stable model usage step id is invalid: %v %v", first, replay)
	}
	if strings.Contains(*first, "request-secret-fixture") {
		t.Fatal("step ID must not expose the raw request key")
	}
	otherRequest := StableModelUsageStepID(scope, "different-request")
	otherScope := scope
	otherScope.RunID = "another-run"
	otherRun := StableModelUsageStepID(otherScope, "request-secret-fixture")
	if otherRequest == nil || otherRun == nil || *first == *otherRequest || *first == *otherRun {
		t.Fatal("step ID must bind both request and complete Run scope")
	}
	if StableModelUsageStepID(scope, "request\x00fixture") != nil {
		t.Fatal("invalid request key must not produce a stable step ID")
	}
	if StableModelUsageStepID(scope, strings.Repeat("k", 200)) == nil {
		t.Fatal("step ID derivation must support the model invocation store's 255-byte key limit")
	}
}

func TestUsageEventsEqualComparesDecodedStepIDsByValueAndKeepsLegacyNull(t *testing.T) {
	leftStep, rightStep := "model-step-same", "model-step-same"
	left := Event{ID: "event", Scope: testUsageScope(), Provider: "p", Model: "m", InputTokens: 2, OutputTokens: 3, CostMicros: 4, StepID: &leftStep}
	right := left
	right.StepID = &rightStep
	if !UsageEventsEqual(left, right) {
		t.Fatal("independently decoded equal step ID strings must compare equal by value")
	}
	different := right
	differentStep := "model-step-different"
	different.StepID = &differentStep
	if UsageEventsEqual(left, different) {
		t.Fatal("a mismatched stable step ID must not pass an authority comparison")
	}
	legacyLeft, legacyRight := left, right
	legacyLeft.StepID, legacyRight.StepID = nil, nil
	if !UsageEventsEqual(legacyLeft, legacyRight) {
		t.Fatal("independently decoded pre-migration events with NULL step IDs must still compare equal")
	}
	if UsageEventsEqual(legacyLeft, right) {
		t.Fatal("a missing historical step link must not silently match a newly supplied link")
	}
	different.CostMicros++
	different.StepID = &leftStep
	if UsageEventsEqual(left, different) {
		t.Fatal("step identity comparison must retain every original billing dimension")
	}
	different = right
	different.Scope.RunID = "another-run"
	if UsageEventsEqual(left, different) {
		t.Fatal("step identity comparison must retain the complete Run scope")
	}
}

func TestLedgerStepIDReplayKeepsLegacyNullAndRejectsKnownMismatch(t *testing.T) {
	l := NewLedger()
	event := Event{ID: "legacy-model-event", Scope: testUsageScope(), Provider: "p", Model: "m", InputTokens: 2, CostMicros: 3}
	if _, err := l.Apply(event); err != nil {
		t.Fatal(err)
	}
	stepID := "model-step-fixture"
	withStep := event
	withStep.StepID = &stepID
	if _, err := l.Apply(withStep); err != nil {
		t.Fatalf("old null step ID must be compatible with exact billed replay: %v", err)
	}
	if l.events[event.ID].StepID != nil {
		t.Fatal("replay must not backfill an unknown historical step ID")
	}
	known := Event{ID: "known-model-event", Scope: testUsageScope(), Provider: "p", Model: "m", InputTokens: 2, CostMicros: 3, StepID: &stepID}
	if _, err := l.Apply(known); err != nil {
		t.Fatal(err)
	}
	different := known
	otherStepID := "model-step-other"
	different.StepID = &otherStepID
	if _, err := l.Apply(different); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("known step ID conflict must be rejected: %v", err)
	}
}

func TestLedgerAppliesUsageIdempotentlyAndRejectsBudgetOverflow(t *testing.T) {
	l := NewLedger()
	scope := testUsageScope()
	if err := l.SetBudget(Budget{ScopeKey: ScopeKey(scope), LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	e := Event{ID: "event-1", Scope: scope, Provider: "local", Model: "model", InputTokens: 2, OutputTokens: 3, CostMicros: 60}
	first, err := l.Apply(e)
	if err != nil || first.UsedMicros != 60 {
		t.Fatalf("first usage: %+v err=%v", first, err)
	}
	replay, err := l.Apply(e)
	if err != nil || replay.UsedMicros != 60 {
		t.Fatalf("replay must not double count: %+v err=%v", replay, err)
	}
	if _, err = l.Apply(Event{ID: "event-2", Scope: scope, CostMicros: 50}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected budget rejection, got %v", err)
	}
	if _, err = l.Apply(Event{ID: "event-1", Scope: scope, CostMicros: 61}); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	if _, err = l.Apply(Event{ID: "event-1", Scope: scope, Provider: "other", Model: "model", InputTokens: 2, OutputTokens: 3, CostMicros: 60}); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("provider changes must conflict, got %v", err)
	}
}

func TestLedgerRequiresCompleteScope(t *testing.T) {
	l := NewLedger()
	_, err := l.Apply(Event{ID: "event", Scope: Scope{TenantID: "tenant", ApplicationID: "app", RunID: "run"}, CostMicros: 1})
	if !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("incomplete scope must be rejected, got %v", err)
	}
}

func TestLedgerRejectsCounterOverflow(t *testing.T) {
	l := NewLedger()
	scope := testUsageScope()
	if _, err := l.Apply(Event{ID: "event-1", Scope: scope, CostMicros: maxInt64}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Apply(Event{ID: "event-2", Scope: scope, CostMicros: 1}); !errors.Is(err, ErrInvalidUsage) {
		t.Fatalf("counter overflow must be rejected, got %v", err)
	}
}

func TestLedgerUsageReadModelsRespectScopeTimeAndPagination(t *testing.T) {
	l := NewLedger()
	scope := testUsageScope()
	start := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	for _, event := range []Event{
		{ID: "event-1", Scope: scope, InputTokens: 3, OutputTokens: 2, CostMicros: 5},
		{ID: "event-2", Scope: scope, InputTokens: 7, OutputTokens: 4, CostMicros: 11},
		{ID: "event-other", Scope: Scope{TenantID: "other", DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID, RunID: scope.RunID}, InputTokens: 100, CostMicros: 100},
	} {
		if _, err := l.Apply(event); err != nil {
			t.Fatal(err)
		}
	}
	l.createdAt["event-1"] = start.Add(time.Hour)
	l.createdAt["event-2"] = start.Add(2 * time.Hour)
	l.createdAt["event-other"] = start.Add(time.Hour)
	aggregate, err := l.AggregateUsage(context.Background(), scope, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.EventCount != 2 || aggregate.InputTokens != 10 || aggregate.OutputTokens != 6 || aggregate.CostMicros != 16 {
		t.Fatalf("unexpected aggregate: %+v", aggregate)
	}
	page, err := l.ListUsageEvents(context.Background(), scope, start, end, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Page != 1 || page.PageSize != 1 || len(page.Items) != 1 || page.Items[0].Event.ID != "event-2" {
		t.Fatalf("unexpected first execution page: %+v", page)
	}
	page, err = l.ListUsageEvents(context.Background(), scope, start, end, 2, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].Event.ID != "event-1" {
		t.Fatalf("unexpected second execution page: %+v err=%v", page, err)
	}
	if _, err := l.AggregateUsage(context.Background(), Scope{}, start, end); !errors.Is(err, ErrInvalidUsageQuery) {
		t.Fatalf("empty scope must fail closed, got %v", err)
	}
	if _, err := l.ListUsageEvents(context.Background(), scope, start, end, 1, MaxUsagePageSize+1); !errors.Is(err, ErrInvalidUsageQuery) {
		t.Fatalf("oversized page must be rejected, got %v", err)
	}
}

func TestLedgerGroupsUsageRunsAndPagesOrderedSteps(t *testing.T) {
	l := NewLedger()
	scope := testUsageScope()
	start := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	stepID := "model-step-a"
	events := []Event{
		{ID: "run-a-step-1", StepID: &stepID, Scope: scope, Provider: "p1", Model: "m1", InputTokens: 2, OutputTokens: 1, CostMicros: 3},
		{ID: "run-a-step-2", Scope: scope, Provider: "p2", Model: "m2", InputTokens: 4, OutputTokens: 3, CostMicros: 7},
	}
	otherRun := scope
	otherRun.RunID = "run-b"
	events = append(events, Event{ID: "run-b-step-1", Scope: otherRun, CostMicros: 5})
	for _, event := range events {
		if _, err := l.Apply(event); err != nil {
			t.Fatal(err)
		}
	}
	l.createdAt["run-a-step-1"] = start.Add(time.Hour)
	l.createdAt["run-a-step-2"] = start.Add(2 * time.Hour)
	l.createdAt["run-b-step-1"] = start.Add(3 * time.Hour)
	filter := scope
	filter.RunID = ""
	runs, err := l.ListRuns(context.Background(), filter, start, start.Add(24*time.Hour), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if runs.Total != 2 || len(runs.Items) != 1 || runs.Items[0].RunID != "run-b" || runs.Items[0].EventCount != 1 {
		t.Fatalf("run page must group and bound summaries: %+v", runs)
	}
	runs, err = l.ListRuns(context.Background(), filter, start, start.Add(24*time.Hour), 2, 1)
	if err != nil || len(runs.Items) != 1 || runs.Items[0].RunID != "run" || runs.Items[0].EventCount != 2 || runs.Items[0].InputTokens != 6 || runs.Items[0].OutputTokens != 4 || runs.Items[0].CostMicros != 10 {
		t.Fatalf("run summary does not match ledger events: %+v err=%v", runs, err)
	}
	steps, err := l.ListRunSteps(context.Background(), scope, start, start.Add(24*time.Hour), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if steps.Total != 2 || len(steps.Items) != 1 || steps.Items[0].Index != 1 || steps.Items[0].EventID != "run-a-step-1" || steps.Items[0].StepID == nil || *steps.Items[0].StepID != stepID {
		t.Fatalf("unexpected first run-step page: %+v", steps)
	}
	steps, err = l.ListRunSteps(context.Background(), scope, start, start.Add(24*time.Hour), 2, 1)
	if err != nil || len(steps.Items) != 1 || steps.Items[0].Index != 2 || steps.Items[0].EventID != "run-a-step-2" || steps.Items[0].StepID != nil {
		t.Fatalf("unexpected second run-step page: %+v err=%v", steps, err)
	}
	filter.RunID = ""
	if _, err := l.ListRunSteps(context.Background(), filter, start, start.Add(24*time.Hour), 1, 1); !errors.Is(err, ErrInvalidUsageQuery) {
		t.Fatalf("run-step query must require one run ID, got %v", err)
	}
}
