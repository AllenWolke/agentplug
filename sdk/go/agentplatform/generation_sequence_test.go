package agentplatform

import (
	"reflect"
	"testing"
)

// This verifies cursor ordering only. A fresh Store is not a recovery proof;
// the execution transport must establish stop/checkpoint authority separately.
func TestGenerationEventsRemainVisibleAfterProcessReplacement(t *testing.T) {
	scope := ScopeKey{RunID: "generation-cursor", PrincipalID: "owner"}
	old := NewMemoryRunStore()
	if _, created, err := old.StartGeneration(scope, "same-input", 1); err != nil || !created {
		t.Fatalf("first generation not created: %v", err)
	}
	last, err := old.AppendEvent(scope.RunID, EventProgress, map[string]any{"operation": "inspect"})
	if err != nil {
		t.Fatal(err)
	}
	replacement := NewMemoryRunStore()
	if _, created, err := replacement.StartGeneration(scope, "same-input", 2); err != nil || !created {
		t.Fatalf("replacement projection not created: %v", err)
	}
	events, err := replacement.EventsAfter(scope.RunID, last.Seq)
	if err != nil || len(events) != 1 || events[0].EventType != EventAccepted || events[0].Seq <= last.Seq {
		t.Fatalf("old cursor hid the real new event: %v, %v", events, err)
	}
	if _, created, err := replacement.StartGeneration(scope, "same-input", 2); err != nil || created {
		t.Fatalf("same-generation replay created work: %v", err)
	}
	replayed, _ := replacement.EventsAfter(scope.RunID, last.Seq)
	if len(replayed) != 1 || replayed[0].Seq != events[0].Seq {
		t.Fatal("replay changed the actual event history")
	}
}

func TestGenerationResumePreservesActualWaitingEvents(t *testing.T) {
	scope := ScopeKey{RunID: "generation-waiting", PrincipalID: "owner"}
	store := NewMemoryRunStore()
	if _, _, err := store.StartGeneration(scope, "same-input", 1); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkWaiting(scope.RunID, map[string]any{"reason": "approval_required"}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.GetRun(scope.RunID)
	if err := store.ResumeGeneration(scope, "same-input", 3); err != nil {
		t.Fatal(err)
	}
	after, _ := store.GetRun(scope.RunID)
	if len(after.Events) != len(before.Events)+1 || after.Status != RunStatusRunning {
		t.Fatal("resume did not append exactly one real started event")
	}
	for index, event := range before.Events {
		if after.Events[index].Seq != event.Seq || after.Events[index].EventType != event.EventType {
			t.Fatal("resume rewrote old actual events")
		}
	}
	last := after.Events[len(after.Events)-1]
	if last.EventType != EventStarted || last.Seq <= before.Events[len(before.Events)-1].Seq {
		t.Fatal("resumed event does not advance the cursor")
	}
}

func TestGenerationRejectsForeignScopeAndOutOfRangeRevision(t *testing.T) {
	scope := ScopeKey{RunID: "generation-owner", PrincipalID: "owner"}
	store := NewMemoryRunStore()
	if _, _, err := store.StartGeneration(scope, "same-input", 1); err != nil {
		t.Fatal(err)
	}
	foreign := scope
	foreign.PrincipalID = "other"
	if _, _, err := store.StartGeneration(foreign, "same-input", 1); err == nil {
		t.Fatal("foreign owner reused the projection")
	}
	for _, revision := range []uint64{0, (1 << 33) + 1} {
		if _, _, err := store.StartGeneration(ScopeKey{RunID: "invalid-revision"}, "same-input", revision); err == nil {
			t.Fatal("invalid revision allocated an event range")
		}
	}
	if _, exists := store.GetRun("invalid-revision"); exists {
		t.Fatal("invalid admission partially created a Run")
	}
	boundary := NewMemoryRunStore()
	if _, _, err := boundary.StartGeneration(ScopeKey{RunID: "max-revision"}, "same-input", 1<<33); err != nil {
		t.Fatal(err)
	}
	events, err := boundary.EventsAfter("max-revision", 0)
	if err != nil || len(events) != 1 || events[0].Seq >= 1<<53 {
		t.Fatal("boundary event is not a safe integer")
	}
}

func TestGenerationEventExhaustionDoesNotPartiallyCommitLifecycle(t *testing.T) {
	mutations := map[string]func(*MemoryRunStore, string) error{
		"append": func(store *MemoryRunStore, id string) error {
			_, err := store.AppendEvent(id, EventProgress, map[string]any{})
			return err
		},
		"waiting": func(store *MemoryRunStore, id string) error {
			return store.MarkWaiting(id, map[string]any{"reason": "approval_required"})
		},
		"complete": func(store *MemoryRunStore, id string) error {
			return store.Complete(id, map[string]any{"answer": "must not be stored"})
		},
		"fail": func(store *MemoryRunStore, id string) error {
			return store.Fail(id, AppError{Code: "MUST_NOT_BE_STORED"})
		},
		"cancel": func(store *MemoryRunStore, id string) error {
			_, err := store.Cancel(id, "must not cancel")
			return err
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			store := NewMemoryRunStore()
			id := "range-exhaustion-" + name
			if _, _, err := store.StartGeneration(ScopeKey{RunID: id}, "same-input", 1); err != nil {
				t.Fatal(err)
			}
			// Seed the capacity boundary directly: the test must exercise the
			// atomic rejection without allocating a million event payloads.
			store.mu.Lock()
			store.runs[id].record.Events[0].Seq = (1 << 20) - 1
			store.mu.Unlock()
			before, _ := store.GetRun(id)
			if err := mutate(store, id); err == nil {
				t.Fatal("exhausted generation accepted a lifecycle mutation")
			}
			after, _ := store.GetRun(id)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("rejected event partially changed status, output or history")
			}
			cancelled, _ := store.Cancelled(id)
			select {
			case <-cancelled:
				t.Fatal("rejected event signalled cancellation")
			default:
			}
		})
	}
}
