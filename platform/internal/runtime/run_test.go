package runtime

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func scope() sharedkernel.Scope {
	return sharedkernel.Scope{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalID: "p", AgentInstanceID: "i"}
}

func TestCreateIsIdempotentAndScoped(t *testing.T) {
	s := NewStore()
	req := CreateRequest{ID: "run-1", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "idem-1", Fingerprint: "body-1"}
	first, err := s.Create(req)
	if err != nil || first.Replayed {
		t.Fatalf("first create failed: %+v, %v", first, err)
	}
	second, err := s.Create(CreateRequest{ID: "run-2", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "idem-1", Fingerprint: "body-1"})
	if err != nil || !second.Replayed || second.Run.ID != "run-1" {
		t.Fatalf("replay failed: %+v, %v", second, err)
	}
	_, err = s.Create(CreateRequest{ID: "run-3", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "idem-1", Fingerprint: "body-2"})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestConcurrentCreateHasOneWinner(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	results := make(chan CreateResult, 16)
	errs := make(chan error, 16)
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			result, err := s.Create(CreateRequest{ID: "run-" + string(rune('a'+n)), Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "same", Fingerprint: "same-body"})
			results <- result
			errs <- err
		}(n)
	}
	wg.Wait()
	close(results)
	close(errs)
	var created int
	for result := range results {
		if !result.Replayed {
			created++
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if created != 1 {
		t.Fatalf("expected one creator, got %d", created)
	}
}

func TestTransitionLeaseAndEventReplay(t *testing.T) {
	s := NewStore()
	created, err := s.Create(CreateRequest{ID: "run", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "idem", Fingerprint: "body"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.Transition(created.Run.ID, StatusAccepted, StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	run, err = s.AcquireLease(run.ID, "lease-a", time.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Heartbeat(run.ID, "lease-b", run.Revision, time.Now(), time.Minute); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("expected fencing conflict, got %v", err)
	}
	events, err := s.Events(run.ID, 0)
	if err != nil || len(events) < 2 || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("event replay failed: %+v, %v", events, err)
	}
}

func TestPrepareResumePersistsInputAndMovesWaitingToRunning(t *testing.T) {
	s := NewStore()
	raw := []byte(`{"protocol_version":"agent-execution/v2","operation":"run","input":{"question":"q"},"context_token":"ctx"}`)
	created, err := s.Create(CreateRequest{ID: "resume", Scope: scope(), AgentVersionID: "v1", IdempotencyKey: "resume-idem", Fingerprint: "resume-body", RequestJSON: raw})
	if err != nil {
		t.Fatal(err)
	}
	running, err := s.Transition(created.Run.ID, StatusAccepted, StatusRunning, created.Run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := s.Transition(running.ID, StatusRunning, StatusWaiting, running.Revision)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := s.PrepareResume(waiting.ID, []byte(`{"approved":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Status != StatusRunning || resumed.Revision != waiting.Revision+1 {
		t.Fatalf("unexpected resumed run: %+v", resumed)
	}
	var envelope map[string]any
	if err := json.Unmarshal(resumed.RequestJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["operation"] != "run" || string(resumed.ResumeInputJSON) != `{"approved":true}` {
		t.Fatalf("resume envelope not persisted: request=%s input=%s", resumed.RequestJSON, resumed.ResumeInputJSON)
	}
}
