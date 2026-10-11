// Package postgresintegration tests real cross-module PostgreSQL transactions.
// Fixtures use separate migration/runtime identities, never project databases.
package postgresintegration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/agentfactory"
	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestMain(m *testing.M) {
	if dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"); dsn != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		db, err := sqlutil.OpenPostgres(ctx, dsn)
		if err != nil {
			fmt.Println("fixture migration connection failed")
			os.Exit(1)
		}
		steps := []func(context.Context) error{catalog.NewSQLStore(db, "pgx").EnsureSchema, agentfactory.NewSQLStore(db).EnsureSchema, audit.NewSQLStore(db).EnsureSchema, notification.NewSQLStore(db).EnsureSchema}
		for _, step := range steps {
			if err := step(ctx); err != nil {
				fmt.Printf("foundation schema migration failed: %v\n", err)
				db.Close()
				cancel()
				os.Exit(1)
			}
		}
		db.Close()
		cancel()
	}
	os.Exit(m.Run())
}

func runtimeDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL runtime fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func testID(t *testing.T) string { return fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()) }

func TestPostgresCatalogCASAndUniqueConflict(t *testing.T) {
	db := runtimeDB(t)
	store := catalog.NewSQLStore(db, "pgx")
	ctx := context.Background()
	id := testID(t)
	d := catalog.Definition{ID: id, PublisherID: "publisher", AgentKey: id, DisplayName: "Example", Description: "Scoped example", Status: catalog.DefinitionDraft, Revision: 1}
	if err := store.CreateDefinition(ctx, d); err != nil {
		t.Fatal(err)
	}
	duplicate := d
	duplicate.ID = id + "-duplicate"
	if err := store.CreateDefinition(ctx, duplicate); !errors.Is(err, catalog.ErrCatalogConflict) {
		t.Fatalf("unique conflict lost: %v", err)
	}
	if err := store.TransitionDefinition(ctx, id, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionDefinition(ctx, id, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1); !errors.Is(err, catalog.ErrRevisionConflict) {
		t.Fatalf("stale revision changed definition: %v", err)
	}
	got, err := store.GetDefinition(ctx, id)
	if err != nil || got.Revision != 2 || got.Status != catalog.DefinitionEvaluated || got.Description != d.Description {
		t.Fatalf("definition projection lost: %#v %v", got, err)
	}
}

func TestPostgresFactoryIsolationAndScopedPagination(t *testing.T) {
	db := runtimeDB(t)
	s := agentfactory.NewSQLStore(db)
	ctx := context.Background()
	id := fmt.Sprintf("template-%d", time.Now().UnixNano())
	scope := agentfactory.Scope{TenantID: id, DepartmentID: "d", ApplicationID: "a"}
	for _, suffix := range []string{"1", "2"} {
		r := agentfactory.Template{ID: id + suffix, Scope: scope, TemplateID: id + suffix, Name: "Example", Language: "go", Framework: "sdk", Status: agentfactory.StatusDraft, CreatedBy: "author", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		if err := s.CreateTemplate(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.ListTemplates(ctx, scope, 1, "")
	if err != nil || len(rows) != 1 || rows[0].ID != id+"2" {
		t.Fatalf("scoped first page: %v %v", rows, err)
	}
	rows, err = s.ListTemplates(ctx, scope, 1, id+"2")
	if err != nil || len(rows) != 1 || rows[0].ID != id+"1" {
		t.Fatalf("dynamic predicate parameter order: %v %v", rows, err)
	}
	foreign := scope
	foreign.ApplicationID = "other"
	if _, err := s.GetTemplate(ctx, foreign, id+"1"); !errors.Is(err, agentfactory.ErrNotFound) {
		t.Fatal("foreign application read template")
	}
}

func TestPostgresAuditOutboxAtomicityAndConcurrentIdempotency(t *testing.T) {
	db := runtimeDB(t)
	ctx := context.Background()
	id := testID(t)
	outbox := notification.NewSQLStore(db)
	store := audit.NewSQLStoreWithOutbox(db, outbox)
	e := audit.Event{ID: id, TenantID: "tenant", DepartmentID: "d", ApplicationID: "a", ActorType: "user", ActorID: "author", TraceID: "trace", AggregateType: "test", AggregateID: id, Action: "created", Outcome: "success", Summary: "redacted", CreatedAt: time.Now().UTC()}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTx(tx, e); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"platform_audit_event", "platform_notification_outbox"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE event_id IN ($1,$2)`, id, "audit-"+id).Scan(&count); err != nil || count != 0 {
			t.Fatal("rollback leaked audit/outbox", err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- store.Record(ctx, e) }()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent idempotent audit failed: %v", err)
		}
	}
	for _, table := range []string{"platform_audit_event", "platform_notification_outbox"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE event_id IN ($1,$2)`, id, "audit-"+id).Scan(&count); err != nil || count != 1 {
			t.Fatal("duplicate/lost atomic event", err)
		}
	}
	e.Summary = "different"
	if err := store.Record(ctx, e); !errors.Is(err, audit.ErrConflict) {
		t.Fatal("audit id reused with changed content")
	}
}

func TestPostgresConcurrentOutboxTransactionsRemainCommittable(t *testing.T) {
	db := runtimeDB(t)
	ctx := context.Background()
	s := notification.NewSQLStore(db)
	id := testID(t)
	e := notification.Event{ID: id, TenantID: "tenant", DepartmentID: "d", ApplicationID: "a", Topic: "test", EventType: "test.event", PartitionKey: id, Payload: map[string]any{"value": "same"}, NextAttemptAt: time.Now().UTC()}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				results <- err
				return
			}
			defer tx.Rollback()
			if _, err := s.EnqueueTx(ctx, tx, e); err != nil {
				results <- err
				return
			}
			results <- tx.Commit()
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("idempotent outbox poisoned caller transaction: %v", err)
		}
	}
	e.Payload = map[string]any{"value": "different"}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := s.EnqueueTx(ctx, tx, e); !errors.Is(err, notification.ErrConflict) {
		t.Fatal("changed outbox content accepted")
	}
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatal("domain conflict aborted SQL transaction")
	}
}

func TestPostgresConcurrentDeliveryClaimAndOwnerFence(t *testing.T) {
	db := runtimeDB(t)
	s := notification.NewSQLStore(db)
	id := testID(t)
	e := notification.Event{ID: id}
	now := time.Now().UTC()
	start := make(chan struct{})
	results := make(chan error, 8)
	winners := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			owner := fmt.Sprintf("worker-%d", i)
			claim, err := s.ClaimDelivery(e, owner, now, time.Minute)
			if err != nil && !errors.Is(err, notification.ErrDeliveryInProgress) {
				results <- err
				return
			}
			if claim.Acquired {
				winners <- owner
			}
			results <- nil
		}(i)
	}
	close(start)
	wg.Wait()
	close(winners)
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var winner string
	count := 0
	for owner := range winners {
		winner = owner
		count++
	}
	if count != 1 {
		t.Fatalf("delivery acquired by %d workers", count)
	}
	if err := s.MarkDeliverySucceeded(id, "wrong-owner"); !errors.Is(err, notification.ErrClaimLost) {
		t.Fatal("wrong owner completed delivery")
	}
	if err := s.MarkDeliverySucceeded(id, winner); err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimDelivery(e, "new-worker", now.Add(2*time.Minute), time.Minute)
	if err != nil || !claim.Delivered || claim.Acquired {
		t.Fatal("completed delivery claimed again", err)
	}
}

func TestPostgresFoundationRuntimeCannotChangeSchema(t *testing.T) {
	db := runtimeDB(t)
	_, err := db.ExecContext(context.Background(), `CREATE TABLE public.runtime_must_not_create_table (id integer)`)
	if sqlutil.SQLState(err) != "42501" {
		t.Fatalf("runtime DDL was not denied by PostgreSQL permissions: %v", err)
	}
}
