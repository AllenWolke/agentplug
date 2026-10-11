package runtime

import (
	"errors"
	"testing"
	"time"
)

func TestAtomicOutcomeFencesOwnerAndRejectsUnserializableOutput(t *testing.T) {
	s := NewStore()
	created, err := s.Create(CreateRequest{ID: "outcome", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "outcome", Fingerprint: "body"})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	running, err := s.TransitionLeased(claimed.ID, StatusAccepted, StatusRunning, claimed.Revision, "owner")
	if err != nil {
		t.Fatal(err)
	}
	// Bad owner and bad JSON must change neither state nor events/outbox.
	// 非法所有者与不可序列化 JSON 必须零状态、事件和待办写入。
	if _, err := s.FinalizeLeased(running.ID, StatusSucceeded, running.Revision, "intruder", map[string]any{"answer": "wrong"}, nil); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("owner fence: %v", err)
	}
	if _, err := s.FinalizeLeased(running.ID, StatusSucceeded, running.Revision, "owner", map[string]any{"bad": make(chan int)}, nil); err == nil {
		t.Fatal("bad JSON accepted")
	}
	unchanged, _ := s.Get(running.ID)
	events, _ := s.Events(running.ID, 0)
	outcomes, _ := s.PendingOutcomes(10)
	if unchanged.Status != StatusRunning || len(events) != 2 || len(outcomes) != 0 {
		t.Fatal("failed finalize left partial writes")
	}
	final, err := s.FinalizeLeased(running.ID, StatusSucceeded, running.Revision, "owner", map[string]any{"answer": "evidence-backed"}, map[string]any{"source": "test"})
	if err != nil {
		t.Fatal(err)
	}
	outcomes, _ = s.PendingOutcomes(10)
	events, _ = s.Events(running.ID, 0)
	if len(outcomes) != 1 || outcomes[0].Revision != final.Revision || string(outcomes[0].OutputJSON) != `{"answer":"evidence-backed"}` || len(events) != 4 || events[3].Type != "task_completed" {
		t.Fatalf("partial finalization: %+v %+v", outcomes, events)
	}
	if err := s.AcknowledgeOutcome(final.ID, final.Revision-1); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale projection acknowledgment: %v", err)
	}
	if err := s.AcknowledgeOutcome(final.ID, final.Revision); err != nil {
		t.Fatal(err)
	}
	outcomes, _ = s.PendingOutcomes(10)
	if len(outcomes) != 0 {
		t.Fatal("acknowledged outcome still pending")
	}
}

func TestFinalizedRunsReleaseExecutionAndSessionLease(t *testing.T) {
	for _, status := range []Status{StatusSucceeded, StatusFailed} {
		t.Run(string(status), func(t *testing.T) {
			store := NewStore()
			created, err := store.Create(CreateRequest{ID: "terminal-lease", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "terminal-lease", Fingerprint: "body"})
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := store.AcquireLease(created.Run.ID, "owner", time.Now(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			running, err := store.TransitionLeased(claimed.ID, StatusAccepted, StatusRunning, claimed.Revision, "owner")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.FinalizeLeased(running.ID, status, running.Revision, "other-owner", nil, nil); !errors.Is(err, ErrLeaseConflict) {
				t.Fatalf("foreign owner unexpectedly finalized: %v", err)
			}
			before, err := store.Get(running.ID)
			if err != nil || before.LeaseToken != "owner" || before.LeaseUntil.IsZero() {
				t.Fatal("denied finalization changed execution ownership")
			}
			final, err := store.FinalizeLeased(running.ID, status, running.Revision, "owner", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := store.Get(running.ID)
			if err != nil || final.Status != status || final.LeaseToken != "" || !final.LeaseUntil.IsZero() || stored.LeaseToken != "" || !stored.LeaseUntil.IsZero() {
				t.Fatal("terminal outcome retained execution ownership")
			}
			if _, exists := store.sessions[SessionExecutionKey(running.Scope)]; exists {
				t.Fatal("terminal outcome retained its session lease")
			}
			if _, err := store.Heartbeat(running.ID, "owner", final.Revision, time.Now(), time.Minute); !errors.Is(err, ErrLeaseConflict) {
				t.Fatalf("old owner renewed terminal execution: %v", err)
			}
		})
	}
}
