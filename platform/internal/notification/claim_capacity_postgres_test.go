package notification

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLOutboxClaimUsesActiveIndexAndSingleConnection(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("owned PostgreSQL migration and DML identities required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err = NewSQLStore(admin).EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer admin.ExecContext(context.Background(), `DELETE FROM platform_notification_outbox WHERE event_id LIKE 'claim-capacity-published-%' OR event_id LIKE 'claim-ready-%'`)
	var fixtureTime time.Time
	if err = db.QueryRowContext(ctx, `SELECT LEAST(COALESCE(MIN(next_attempt_at),clock_timestamp()),clock_timestamp()) - INTERVAL '1 hour' FROM platform_notification_outbox`).Scan(&fixtureTime); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO platform_notification_outbox(event_id,tenant_id,department_id,application_id,topic,event_type,partition_key,payload_json,status,next_attempt_at)
 SELECT 'claim-capacity-published-'||i,'t','d','a','notify','done','partition','{}','published',clock_timestamp() FROM generate_series(1,20000) i`); err != nil {
		t.Fatal(err)
	}
	store := NewSQLStore(db)
	for i := 0; i < 3; i++ {
		e := eventFixture()
		e.ID = fmt.Sprintf("claim-ready-%d", i)
		e.NextAttemptAt = fixtureTime
		if _, err = store.Enqueue(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = admin.ExecContext(ctx, `ANALYZE platform_notification_outbox`); err != nil {
		t.Fatal(err)
	}
	var plan string
	if err = db.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) SELECT event_id FROM platform_notification_outbox WHERE next_attempt_at<=clock_timestamp() AND status IN ('pending','failed','publishing') AND (status IN ('pending','failed') OR (status='publishing' AND claim_until<=clock_timestamp())) ORDER BY next_attempt_at,event_id LIMIT 20`).Scan(&plan); err != nil || !strings.Contains(plan, "idx_notification_active_ready") {
		t.Fatal("claim still scans published history", err, plan)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	type result struct {
		events []Event
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, e := store.Claim("current-owner", 20, fixtureTime, time.Minute)
		done <- result{events, e}
	}()
	var got result
	select {
	case got = <-done:
	case <-time.After(2 * time.Second):
		// Unblock the old nested connection defect, so a failing test never
		// leaves a stuck goroutine or database handle behind.
		db.SetMaxOpenConns(2)
		<-done
		t.Fatal("claim holds its read connection while requesting a second connection")
	}
	if got.err != nil || len(got.events) != 3 {
		t.Fatal("eligible events not claimed", len(got.events), got.err)
	}
	for _, e := range got.events {
		if e.Status != Publishing || e.ClaimOwner != "current-owner" {
			t.Fatal("claim owner/phase changed", e.ID)
		}
		if err = store.MarkPublished(e.ID, "wrong-owner"); err == nil {
			t.Fatal("foreign owner completed event")
		}
		if err = store.MarkPublished(e.ID, "current-owner"); err != nil {
			t.Fatal(err)
		}
	}
	if again, e := store.Claim("current-owner", 20, fixtureTime, time.Minute); e != nil || len(again) != 0 {
		t.Fatal("published event was claimed again", len(again), e)
	}
}
