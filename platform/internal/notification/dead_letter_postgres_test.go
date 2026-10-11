package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/segmentio/kafka-go"
)

func deadLetterDatabase(t *testing.T) (*sql.DB, *SQLDeadLetterStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, e := sqlutil.OpenPostgres(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if e = ApplyDeadLetterSchema(ctx, db); e != nil {
		t.Fatal(e)
	}
	if e = CheckDeadLetterSchema(ctx, db); e != nil {
		t.Fatal(e)
	}
	s, e := NewSQLDeadLetterStore(db)
	if e != nil {
		t.Fatal(e)
	}
	return db, s, ctx
}

func TestDeadLetterPostgresRestartsKeepAttemptBudgetAndNoReplay(t *testing.T) {
	db, s, ctx := deadLetterDatabase(t)
	m := kafka.Message{Topic: "events", Offset: time.Now().UnixNano(), Value: []byte(`{"malformed":true}`)}
	source, _ := deadLetterSource("restart-test", m)
	for attempt := 1; attempt <= 2; attempt++ {
		a, e := s.StartAttempt(ctx, source, 2)
		if e != nil || a.Attempts != attempt || a.Exhausted {
			t.Fatal("durable attempt wrong", a, e)
		}
		s, _ = NewSQLDeadLetterStore(db)
	}
	a, e := s.StartAttempt(ctx, source, 2)
	if e != nil || !a.Exhausted || a.Attempts != 2 {
		t.Fatal("restart cleared exhausted budget", a, e)
	}
	record, e := newDeadLetterRecord(source, m, ErrInvalidEvent, 2)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Quarantine(ctx, record); e != nil {
		t.Fatal(e)
	}
	if e = s.Quarantine(ctx, record); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_kafka_dead_letter WHERE source_id=?`), source.ID()).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate quarantine", count, e)
	}
	if e = s.MarkPublished(ctx, source); e != nil {
		t.Fatal(e)
	}
	s, _ = NewSQLDeadLetterStore(db)
	reader := &kafkaReaderFake{messages: []kafka.Message{m}}
	writer := &kafkaWriterFake{}
	bus := &KafkaGoEventBus{reader: reader, writer: writer, group: source.Group, dlqTopic: "dead", max: 2, backoff: time.Nanosecond, deadLetters: s}
	e = bus.ConsumeMessages(ctx, func(context.Context, EventMessage) DeliveryResult {
		t.Fatal("published dead letter replayed forward handler")
		return Ack()
	})
	if !errors.Is(e, errKafkaReaderDone) || len(reader.commits) != 1 || len(writer.messages) != 0 {
		t.Fatal("restart republished or failed offset recovery", e)
	}
	changed := source
	changed.Digest = strings.Repeat("f", 64)
	if _, e = s.StartAttempt(ctx, changed, 2); !errors.Is(e, ErrDeadLetterConflict) {
		t.Fatal("tampered source admitted", e)
	}
}

func TestDeadLetterPostgresActionsAreScopedCASAndAtomic(t *testing.T) {
	db, s, ctx := deadLetterDatabase(t)
	outbox := NewSQLStore(db)
	if e := outbox.EnsureSchema(ctx); e != nil {
		t.Fatal(e)
	}
	scope := sharedkernel.Scope{TenantID: fmt.Sprint("dlq-tenant-", time.Now().UnixNano()), DepartmentID: "dlq-dept", ApplicationID: "dlq-app", PrincipalType: "user", PrincipalID: "operator", TraceID: "trace-one"}
	event, _ := NewAuthorizationChangedEvent(fmt.Sprint(time.Now().UnixNano()), scope.TenantID, scope.DepartmentID, scope.ApplicationID, "user", "target", 2)
	if _, e := outbox.Enqueue(event); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_notification_outbox SET status='published' WHERE event_id=?`), event.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_notification_delivery(event_id,status,attempts,claim_owner,last_error) VALUES(?,'dead',5,'','DELIVERY_FAILED')`), event.ID); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(event)
	m := kafka.Message{Topic: event.Topic, Offset: time.Now().UnixNano(), Value: body}
	source, _ := deadLetterSource("action-test", m)
	if _, e := s.StartAttempt(ctx, source, 2); e != nil {
		t.Fatal(e)
	}
	record, _ := newDeadLetterRecord(source, m, ErrEventDeliveryDeadLetter, 1)
	if e := s.Quarantine(ctx, record); e != nil {
		t.Fatal(e)
	}
	if e := s.MarkPublished(ctx, source); e != nil {
		t.Fatal(e)
	}
	failAudit := true
	rev := uint64(1)
	revoked := false
	if e := s.SetOperations(func(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, action string) error {
		if revoked || actor.PrincipalID != "operator" {
			return ErrDeadLetterUnavailable
		}
		return nil
	}, func(context.Context, *sql.Tx, sharedkernel.Scope, DeadLetterCommand, DeadLetterMetadata) error {
		if failAudit {
			return errors.New("injected audit failure")
		}
		return nil
	}, func(ctx context.Context, tx *sql.Tx, actor sharedkernel.Scope, event Event) error {
		return outbox.PrepareControlEventRedriveTx(ctx, tx, event, func(context.Context, *sql.Tx, string, string, string) (uint64, error) { return rev, nil })
	}); e != nil {
		t.Fatal(e)
	}
	items, e := s.List(ctx, scope, DeadLetterQuery{Limit: 10})
	if e != nil || len(items) != 1 || items[0].ID != source.ID() {
		t.Fatal("scoped list", items, e)
	}
	foreign := scope
	foreign.TenantID = "other"
	if items, e := s.List(ctx, foreign, DeadLetterQuery{Limit: 10}); e != nil || len(items) != 0 {
		t.Fatal("cross-tenant disclosure", e)
	}
	c := DeadLetterCommand{ID: source.ID(), ExpectedRevision: 1, IdempotencyKey: "request-one", Action: "redrive", ReasonCode: "PROVIDER_RECOVERED"}
	if _, e = s.Act(ctx, scope, c); !errors.Is(e, ErrAuthorizationRevision) {
		t.Fatal("future authorization revision redriven", e)
	}
	rev = 3
	if _, e = s.Act(ctx, scope, c); e == nil {
		t.Fatal("audit failure admitted redrive")
	}
	var state string
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_notification_outbox WHERE event_id=?`), event.ID).Scan(&state); e != nil || state != "published" {
		t.Fatal("failed action committed outbox", state, e)
	}
	failAudit = false
	meta, e := s.Act(ctx, scope, c)
	if e != nil || meta.Status != "redrive_pending" || meta.Revision != 2 {
		t.Fatal("redrive rejected", meta, e)
	}
	scope.TraceID = "trace-reconnect"
	if meta, e = s.Act(ctx, scope, c); e != nil || meta.Revision != 2 {
		t.Fatal("reconnect changed idempotency identity", e)
	}
	c.ReasonCode = "changed"
	if _, e = s.Act(ctx, scope, c); !errors.Is(e, ErrDeadLetterConflict) {
		t.Fatal("conflicting request reused", e)
	}
	revoked = true
	if _, e = s.List(ctx, scope, DeadLetterQuery{Limit: 10}); e == nil {
		t.Fatal("revoked operator retained access")
	}
}

func TestDeadLetterPostgresUnknownBusinessEffectCannotBeRedriven(t *testing.T) {
	_, s, ctx := deadLetterDatabase(t)
	scope := sharedkernel.Scope{TenantID: "private-t", DepartmentID: "private-d", ApplicationID: "private-a", PrincipalID: "admin", PrincipalType: "user"}
	event := Event{ID: fmt.Sprint("unknown-", time.Now().UnixNano()), TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID, Topic: "platform.notification", EventType: "agent.notification.requested.v1", PartitionKey: "app", Payload: map[string]any{"body": "PRIVATE_SENTINEL"}}
	body, _ := json.Marshal(event)
	m := kafka.Message{Topic: event.Topic, Offset: time.Now().UnixNano(), Value: body}
	source, _ := deadLetterSource("unknown-test", m)
	s.StartAttempt(ctx, source, 1)
	r, _ := newDeadLetterRecord(source, m, context.DeadlineExceeded, 1)
	if e := s.Quarantine(ctx, r); e != nil {
		t.Fatal(e)
	}
	s.SetOperations(func(context.Context, *sql.Tx, sharedkernel.Scope, string) error { return nil }, func(context.Context, *sql.Tx, sharedkernel.Scope, DeadLetterCommand, DeadLetterMetadata) error {
		return nil
	}, nil)
	if _, e := s.Act(ctx, scope, DeadLetterCommand{ID: source.ID(), ExpectedRevision: 1, IdempotencyKey: "one", Action: "redrive", ReasonCode: "UNKNOWN"}); !errors.Is(e, ErrDeadLetterUnavailable) {
		t.Fatal("unknown business effect redriven", e)
	}
	items, e := s.List(ctx, scope, DeadLetterQuery{Limit: 10})
	raw, _ := json.Marshal(items)
	if e != nil || strings.Contains(string(raw), "PRIVATE_SENTINEL") {
		t.Fatal("private body exposed", e)
	}
}
