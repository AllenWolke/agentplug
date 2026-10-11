package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

type authorizationKafkaObservation struct {
	id     string
	result notification.DeliveryResult
}
type observedAuthorizationKafkaBus struct {
	*notification.KafkaGoEventBus
	observed chan authorizationKafkaObservation
}

func (b *observedAuthorizationKafkaBus) ConsumeMessages(ctx context.Context, handler func(context.Context, notification.EventMessage) notification.DeliveryResult) error {
	return b.KafkaGoEventBus.ConsumeMessages(ctx, func(ctx context.Context, m notification.EventMessage) notification.DeliveryResult {
		result := handler(ctx, m)
		select {
		case b.observed <- authorizationKafkaObservation{m.Event.ID, result}:
		case <-ctx.Done():
		}
		return result
	})
}

type authorizationOutboxFault struct{ notification.TxEnqueuer }

func (f authorizationOutboxFault) EnqueueTx(ctx context.Context, tx *sql.Tx, e notification.Event) (notification.Event, error) {
	_, err := f.TxEnqueuer.EnqueueTx(ctx, tx, e)
	if err != nil {
		return notification.Event{}, err
	}
	return notification.Event{}, errors.New("injected failure after actual version event insert")
}

func TestSQLKafkaAuthorizationEventsAtomicAndDurableReplay(t *testing.T) {
	dsn, broker := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("AUTHORIZATION_ISOLATED_KAFKA_BROKER")
	if dsn == "" || broker == "" {
		t.Skip("isolated PostgreSQL and Kafka required")
	}
	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	name := fmt.Sprintf("authorization_event_fixture_%d", time.Now().UnixNano())
	if _, err = control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	db, err := sqlutil.OpenPostgres(context.Background(), uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	iam, outbox := identity.NewSQLStore(db), notification.NewSQLStore(db)
	auditor := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{iam.EnsureSchema, outbox.EnsureSchema, auditor.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Persisted fixture facts; only the recorder/transport/consumer are under test.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES('subject','user','tenant','[]','[]',TRUE,1,NOW())`)); err != nil {
		t.Fatal(err)
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", PrincipalID: "administrator"}
	write := func(version uint64, fail bool) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=? WHERE principal_type='user' AND id='subject'`), version); err != nil {
			return err
		}
		var writer notification.TxEnqueuer = outbox
		if fail {
			writer = authorizationOutboxFault{outbox}
		}
		receipt := identity.AuthorizationChangeReceipt{ID: fmt.Sprintf("change-%d", version), ActorID: "administrator", SubjectID: "subject", Revision: version, Reason: "isolated event acceptance", OccurredAt: time.Now().UTC(), Change: identity.AuthorizationChangeCommand{SubjectType: identity.PrincipalUser}}
		if err := recordVersionedAuthorizationChange(auditor, writer)(ctx, tx, scope, receipt); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := write(2, false); err != nil {
		t.Fatal(err)
	}
	if err := write(3, false); err != nil {
		t.Fatal(err)
	}
	if err := write(4, true); err == nil {
		t.Fatal("injected transaction failure ignored")
	}
	p, err := iam.GetPrincipal(ctx, identity.PrincipalUser, "subject")
	if err != nil || p.Revision != 3 {
		t.Fatalf("rollback did not retain revision 3: %v", err)
	}
	var eventCount, auditCount int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox`)).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event`)).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 4 || auditCount != 2 {
		t.Fatalf("expected exactly two commits with audit+version events, got %d/%d", eventCount, auditCount)
	}
	// Explicitly take ownership of fixture publication, so the test controls order.
	claimed, err := outbox.Claim("fixture-publisher", 10, time.Now().UTC(), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range claimed {
		if err := outbox.MarkPublished(e.ID, "fixture-publisher"); err != nil {
			t.Fatal(err)
		}
	}
	var reads atomic.Int64
	reader := readAuthorizationRevision(iam)
	adapter := notification.VersionedAuthorizationAdapter{ReadRevision: func(ctx context.Context, tenant, kind, id string) (uint64, error) {
		reads.Add(1)
		return reader(ctx, tenant, kind, id)
	}}
	group := "authorization-" + name
	newModule := func() (*notification.Module, *observedAuthorizationKafkaBus) {
		bus, err := notification.NewKafkaGoEventBus(notification.KafkaGoConfig{Brokers: []string{broker}, ClientID: group, Topic: "platform.audit", AdditionalTopics: []string{"agent-platform.identity.v1"}, GroupID: group, DLQTopic: "platform.notification-dlq.v1", MaxAttempts: 5, RetryBackoff: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		observed := &observedAuthorizationKafkaBus{KafkaGoEventBus: bus, observed: make(chan authorizationKafkaObservation, 16)}
		module := notification.NewModuleWithEventBus(notification.NewSQLStore(db), observed, adapter, "")
		if err := module.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return module, observed
	}
	event := func(change string, revision uint64) notification.Event {
		e, err := notification.NewAuthorizationChangedEvent(change, "tenant", "department", "application", "user", "subject", revision)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	await := func(bus *observedAuthorizationKafkaBus, ids ...string) {
		for _, id := range ids {
			select {
			case observed := <-bus.observed:
				if observed.id != id || observed.result.Action != notification.DeliveryAck {
					t.Fatalf("unexpected delivery %s/%d; want %s/Ack", observed.id, observed.result.Action, id)
				}
			case <-ctx.Done():
				t.Fatal("actual Kafka consumption timed out")
			}
		}
	}
	module, bus := newModule()
	defer module.Close(context.Background())
	for _, e := range []notification.Event{event("change-3", 3), event("change-2", 2), event("change-3", 3), event("marker", 3)} {
		if err := bus.Publish(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	await(bus, "authorization-change-3", "authorization-change-2", "authorization-change-3", "authorization-marker")
	if reads.Load() != 3 {
		t.Fatalf("duplicate not suppressed: %d reads", reads.Load())
	}
	if err := module.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	module2, bus2 := newModule()
	defer module2.Close(context.Background())
	for _, e := range []notification.Event{event("change-3", 3), event("restart-marker", 3)} {
		if err := bus2.Publish(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	await(bus2, "authorization-change-3", "authorization-restart-marker")
	if reads.Load() != 4 {
		t.Fatalf("restart lost durable deduplication: %d reads", reads.Load())
	}
	var delivered int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_delivery WHERE status='published'`)).Scan(&delivered); err != nil {
		t.Fatal(err)
	}
	if delivered != 4 {
		t.Fatalf("expected four durable unique deliveries, got %d", delivered)
	}
	t.Log("Actual PostgreSQL commit/rollback, identity topic subscription, high-before-low ordering, duplicate and restart replay passed; principal revision stayed 3.")
}
