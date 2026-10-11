package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type channelStub struct {
	calls int
	fail  bool
}

func (s *channelStub) Send(context.Context, Event) error {
	s.calls++
	if s.fail {
		return errors.New("channel unavailable")
	}
	return nil
}

func eventFixture() Event {
	return Event{ID: "event-1", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", Topic: "notify", EventType: "task.failed", PartitionKey: "tenant:task", Payload: map[string]any{"task_id": "task"}}
}

func TestOutboxEnqueueReplayAndChannelDispatch(t *testing.T) {
	store := NewStore()
	if _, err := store.Enqueue(eventFixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Enqueue(eventFixture()); err != nil {
		t.Fatalf("same event should replay: %v", err)
	}
	adapter := &channelStub{}
	if err := (Dispatcher{Store: store, Adapter: adapter}).Dispatch(context.Background(), "event-1", "worker"); err != nil {
		t.Fatal(err)
	}
	if adapter.calls != 1 {
		t.Fatalf("calls=%d want 1", adapter.calls)
	}
	if err := (Dispatcher{Store: store, Adapter: adapter}).Dispatch(context.Background(), "event-1", "worker"); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("published event should not be dispatched again: %v", err)
	}
}

func TestOutboxFailureReturnsEventToRetry(t *testing.T) {
	store := NewStore()
	if _, err := store.Enqueue(eventFixture()); err != nil {
		t.Fatal(err)
	}
	adapter := &channelStub{fail: true}
	if err := (Dispatcher{Store: store, Adapter: adapter}).Dispatch(context.Background(), "event-1", "worker"); err == nil || !strings.Contains(err.Error(), "channel unavailable") {
		t.Fatalf("channel failure must propagate after durable retry transition: %v", err)
	}
	if stored := store.events["event-1"]; stored.Status != Failed || stored.Attempts != 1 {
		t.Fatalf("retryable failure must retain failed state: %+v", stored)
	}
	claimed, err := store.Claim("worker-2", 1, timeNow().Add(time.Hour), time.Minute)
	if err != nil || len(claimed) != 1 || claimed[0].Attempts != 1 {
		t.Fatalf("failed event was not retryable: claimed=%+v err=%v", claimed, err)
	}
}

func TestOutboxRejectsCallerSuppliedTerminalStatus(t *testing.T) {
	store := NewStore()
	event := eventFixture()
	event.Status = Published
	if _, err := store.Enqueue(event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("terminal status must not be accepted from producer: %v", err)
	}
}
