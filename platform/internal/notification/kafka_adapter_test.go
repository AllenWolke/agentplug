package notification

import (
	"context"
	"errors"
	"testing"
)

type recordingPublisher struct {
	topic string
	key   string
	body  []byte
	head  map[string]string
	err   error
}

func (p *recordingPublisher) Publish(_ context.Context, topic, key string, body []byte, headers map[string]string) error {
	p.topic, p.key, p.body, p.head = topic, key, body, headers
	return p.err
}

func TestKafkaAdapterPublishesScopedEventWithStableIdempotencyKey(t *testing.T) {
	publisher := &recordingPublisher{}
	adapter := KafkaAdapter{Publisher: publisher}
	event := Event{ID: "evt-1", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", Topic: "agent.events", EventType: "run.completed", PartitionKey: "run-1", Payload: map[string]any{"status": "succeeded"}}
	if err := adapter.Send(context.Background(), event); err != nil {
		t.Fatalf("send: %v", err)
	}
	if publisher.topic != event.Topic || publisher.key != event.PartitionKey {
		t.Fatalf("unexpected topic/key: %q/%q", publisher.topic, publisher.key)
	}
	if publisher.head["idempotency_key"] != event.ID || publisher.head["tenant_id"] != event.TenantID {
		t.Fatalf("missing stable scope/idempotency headers: %#v", publisher.head)
	}
	if len(publisher.body) == 0 {
		t.Fatal("expected JSON body")
	}
}

func TestKafkaAdapterPropagatesPublisherFailure(t *testing.T) {
	want := errors.New("broker unavailable")
	publisher := &recordingPublisher{err: want}
	event := Event{ID: "evt-2", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", Topic: "agent.events", EventType: "run.failed", PartitionKey: "run-2", Payload: map[string]any{"status": "failed"}}
	err := (KafkaAdapter{Publisher: publisher}).Send(context.Background(), event)
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("expected broker error, got %v", err)
	}
}

func TestKafkaAdapterFailsClosedWithoutPublisher(t *testing.T) {
	event := Event{ID: "evt-3", TenantID: "tenant-1", DepartmentID: "dept-1", ApplicationID: "app-1", Topic: "agent.events", EventType: "run.failed", PartitionKey: "run-3", Payload: map[string]any{"status": "failed"}}
	if err := (KafkaAdapter{}).Send(context.Background(), event); !errors.Is(err, ErrAdapterUnavailable) {
		t.Fatalf("expected unavailable adapter, got %v", err)
	}
}
