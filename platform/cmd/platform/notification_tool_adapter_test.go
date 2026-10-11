package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/capability"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type recordingNotificationOutbox struct {
	events []notification.Event
	err    error
}

func (s *recordingNotificationOutbox) Enqueue(event notification.Event) (notification.Event, error) {
	if s.err != nil {
		return notification.Event{}, s.err
	}
	s.events = append(s.events, event)
	if event.Status == "" {
		event.Status = notification.Pending
	}
	return event, nil
}

func TestPlatformNotificationToolAdapterCreatesScopedOutboxEvent(t *testing.T) {
	store := &recordingNotificationOutbox{}
	adapter := platformNotificationToolAdapter{outbox: store}
	command := capability.NotificationToolCommand{
		Scope: sharedkernel.Scope{
			TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a",
			AgentID: "example-agent", AgentVersionID: "v2", InstallationID: "install-a",
			PrincipalType: "user", PrincipalID: "user-a", SessionID: "session-a", RunID: "run-a", TraceID: "trace-a",
		},
		EventID: "agent-tool-stable-id", RecipientID: "reviewer-a", Title: "审核完成", Text: "任务已归档",
	}
	receipt, err := adapter.Enqueue(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.EventID != command.EventID || receipt.Status != string(notification.Pending) || len(store.events) != 1 {
		t.Fatalf("unexpected receipt/events: receipt=%+v events=%+v", receipt, store.events)
	}
	event := store.events[0]
	if event.TenantID != command.Scope.TenantID || event.DepartmentID != command.Scope.DepartmentID || event.ApplicationID != command.Scope.ApplicationID || event.EventType != "agent.notification.requested.v1" || event.PartitionKey != command.Scope.ApplicationID {
		t.Fatalf("outbox event lost its trusted scope/type: %+v", event)
	}
	if event.Payload["recipient_id"] != command.RecipientID || event.Payload["run_id"] != command.Scope.RunID || event.Payload["trace_id"] != command.Scope.TraceID {
		t.Fatalf("outbox payload lost recipient/run/trace data: %#v", event.Payload)
	}
}

func TestPlatformNotificationToolAdapterPropagatesOutboxFailure(t *testing.T) {
	adapter := platformNotificationToolAdapter{outbox: &recordingNotificationOutbox{err: errors.New("database unavailable")}}
	_, err := adapter.Enqueue(context.Background(), capability.NotificationToolCommand{
		Scope:   sharedkernel.Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a"},
		EventID: "event-a", RecipientID: "user-a", Title: "title", Text: "body",
	})
	if err == nil {
		t.Fatal("Outbox errors must reach the Capability boundary")
	}
}
