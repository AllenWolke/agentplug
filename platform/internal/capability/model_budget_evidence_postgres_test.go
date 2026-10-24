package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

// Use real PostgreSQL's planner and the real evidence decoder. This measures
// access shape, not a hardware-dependent latency threshold or model quality.
func TestModelBudgetEvidenceIndexedLookupPostgres(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/knowledge_test" {
		t.Fatal("owned fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("evidence-index-%d", time.Now().UnixNano())
	defer func() {
		if _, err := db.ExecContext(context.Background(), `DELETE FROM platform_model_invocation WHERE scope_hash=$1`, prefix); err != nil {
			t.Error(err)
		}
	}()
	_, err = db.ExecContext(ctx, `INSERT INTO platform_model_invocation(scope_hash,idempotency_key,fingerprint,status,billing_recovery_json,created_at,updated_at)
SELECT $1::text,'padding-'||n,'padding','reconcile',jsonb_build_object('reservation',jsonb_build_object('reservation_id',$1::text||'-'||n))::text,clock_timestamp(),clock_timestamp() FROM generate_series(1,20000) AS n`, prefix)
	if err != nil {
		t.Fatal(err)
	}
	r := usagecost.ModelBudgetReservation{ReservationID: prefix + "-target", Fingerprint: strings.Repeat("a", 64), PriceVersionID: "price-v1"}
	raw, err := json.Marshal(BillingRecovery{Reservation: r, PriceID: r.PriceVersionID})
	if err != nil {
		t.Fatal(err)
	}
	insert := func(key, fingerprint string) {
		t.Helper()
		_, err := db.ExecContext(ctx, `INSERT INTO platform_model_invocation(scope_hash,idempotency_key,fingerprint,status,billing_recovery_json,created_at,updated_at) VALUES($1,$2,$3,'reconcile',$4,clock_timestamp(),clock_timestamp())`, prefix, key, fingerprint, string(raw))
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("original", r.Fingerprint)
	if _, err = db.ExecContext(ctx, `ANALYZE platform_model_invocation`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{r.ReservationID, prefix + "-absent"} {
		var plan string
		if err = db.QueryRowContext(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT scope_hash,idempotency_key,fingerprint,billing_recovery_json FROM platform_model_invocation WHERE billing_recovery_json IS NOT NULL AND (billing_recovery_json::jsonb->'reservation'->>'reservation_id')=$1 LIMIT 2 FOR SHARE`, id).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(plan, `"Index Name": "idx_model_invocation_budget_reservation"`) {
			t.Fatal("reservation proof must use the declared evidence index")
		}
	}
	read := func(reservation usagecost.ModelBudgetReservation) error {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		_, err = store.BudgetEvidenceTx(ctx, tx, reservation)
		return err
	}
	if err = read(r); err != nil {
		t.Fatalf("original evidence: %v", err)
	}
	missing := r
	missing.ReservationID = prefix + "-absent"
	if err = read(missing); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatalf("missing evidence must not authorize accounting: %v", err)
	}
	wrong := r
	wrong.Fingerprint = strings.Repeat("b", 64)
	if err = read(wrong); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatalf("fingerprint mismatch must fail: %v", err)
	}
	insert("duplicate", r.Fingerprint)
	if err = read(r); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatalf("index must preserve duplicate-evidence rejection: %v", err)
	}
}
