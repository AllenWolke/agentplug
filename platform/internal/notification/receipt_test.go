package notification

import (
	"context"
	"testing"
)

func TestCommittedEventLookupIsReadOnlyAndIsolated(t *testing.T) {
	s := NewStore()
	e := Event{ID: "receipt", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", Topic: "topic", EventType: "type", PartitionKey: "application", Payload: map[string]any{"value": "original"}}
	if _, err := s.Enqueue(e); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.FindCommittedEvent(context.Background(), e.ID)
	if err != nil || !found {
		t.Fatal("committed event missing")
	}
	got.Payload["value"] = "changed"
	again, found, err := s.FindCommittedEvent(context.Background(), e.ID)
	if err != nil || !found || again.Payload["value"] != "original" {
		t.Fatal("lookup exposed mutable event")
	}
	if _, found, err := s.FindCommittedEvent(context.Background(), "unknown"); err != nil || found {
		t.Fatal("unknown event was created")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.FindCommittedEvent(ctx, e.ID); err == nil {
		t.Fatal("cancelled lookup ignored context")
	}
}
