package audit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAuditNotificationChannelConfirmsOnlyCommittedScopeBoundEvents(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/knowledge_test" {
		t.Fatal("dedicated fixture database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewSQLStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	record := Event{ID: fmt.Sprintf("audit-channel-%d", time.Now().UnixNano()), TenantID: "fixture", DepartmentID: "compliance", ApplicationID: "business-app", ActorID: "operator", AggregateType: "run", AggregateID: "fixture-run", Action: "complete", Outcome: "success", CreatedAt: time.Now().UTC()}
	if err := store.Record(ctx, record); err != nil {
		t.Fatal(err)
	}
	digest, err := record.Digest()
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{ID: "audit-" + record.ID, TenantID: record.TenantID, DepartmentID: record.DepartmentID, ApplicationID: record.ApplicationID, Topic: "platform.audit", EventType: "audit.complete", PartitionKey: record.AggregateID, Payload: map[string]any{"event_id": record.ID, "digest": digest, "action": record.Action, "aggregate_type": record.AggregateType, "aggregate_id": record.AggregateID, "outcome": record.Outcome}}
	channel := store.NotificationChannel()
	// Actual Kafka publication carries the claimed publishing state.
	// The receiver must use delivery validation, not producer validation.
	for _, state := range []notification.Status{"", notification.Pending, notification.Publishing, notification.Failed} {
		candidate := event
		candidate.Status, candidate.Attempts = state, 2
		if err := channel.Send(ctx, candidate); err != nil {
			t.Fatal("claimed/retried delivery rejected", state, err)
		}
	}
	for _, state := range []notification.Status{notification.Published, notification.Dead} {
		candidate := event
		candidate.Status = state
		if err := channel.Send(ctx, candidate); !errors.Is(err, notification.ErrInvalidEvent) {
			t.Fatal("caller-forged delivery terminal accepted", state, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := channel.Send(ctx, event); err != nil {
			t.Fatal("exact committed audit rejected", err)
		}
	}
	cases := map[string]func(*notification.Event){
		"foreign_tenant":      func(e *notification.Event) { e.TenantID = "other" },
		"foreign_department":  func(e *notification.Event) { e.DepartmentID = "other" },
		"foreign_application": func(e *notification.Event) { e.ApplicationID = "other" },
		"wrong_digest":        func(e *notification.Event) { e.Payload["digest"] = "changed" },
		"wrong_outcome":       func(e *notification.Event) { e.Payload["outcome"] = "failed" },
		"uncommitted": func(e *notification.Event) {
			e.Payload["event_id"] = record.ID + "-missing"
			e.ID = "audit-" + record.ID + "-missing"
		},
		"spoofed_id":      func(e *notification.Event) { e.ID = "audit-spoof" },
		"wrong_partition": func(e *notification.Event) { e.PartitionKey = "other" },
		"business_message": func(e *notification.Event) {
			e.Topic = "platform.notification"
			e.EventType = "agent.notification.requested.v1"
		},
		"extra_payload":      func(e *notification.Event) { e.Payload["body"] = "sensitive fixture content" },
		"wrong_payload_type": func(e *notification.Event) { e.Payload["digest"] = 1 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := event
			candidate.Payload = map[string]any{}
			for k, v := range event.Payload {
				candidate.Payload[k] = v
			}
			change(&candidate)
			if err := channel.Send(ctx, candidate); !errors.Is(err, notification.ErrInvalidEvent) {
				t.Fatal("unverified audit accepted", err)
			}
		})
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if err := channel.Send(cancelled, event); !errors.Is(err, notification.ErrAdapterUnavailable) {
		t.Fatal("cancelled read accepted", err)
	}
	if err := ((*SQLStore)(nil)).NotificationChannel().Send(ctx, event); !errors.Is(err, notification.ErrAdapterUnavailable) {
		t.Fatal("unconfigured owner accepted", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind("SELECT count(*) FROM platform_audit_event WHERE event_id=?"), record.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("receipt read changed audit history", count, err)
	}
}
