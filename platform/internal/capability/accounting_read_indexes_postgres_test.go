package capability

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestSQLAccountingReadIndexesKeepUnknownRowsAndAvoidClosedHistory(t *testing.T) {
	adminDSN, runtimeDSN := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if adminDSN == "" || runtimeDSN == "" {
		t.Skip("owned PostgreSQL migration and DML identities required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	models, _ := NewSQLModelInvocationStore(admin)
	for _, ensure := range []func(context.Context) error{models.EnsureSchema, usagecost.NewSQLStore(admin).EnsureSchema, usagecost.NewSQLRunTreeBudgetStore(admin).EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sqlutil.OpenPostgres(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer db.Exec(`DELETE FROM platform_model_invocation WHERE scope_hash IN ('indexed-closed','indexed-active')`)
	if _, err = db.ExecContext(ctx, `INSERT INTO platform_model_invocation(scope_hash,idempotency_key,fingerprint,status,billing_state,created_at,updated_at)
 SELECT 'indexed-closed',i::text,'fp','completed','done',clock_timestamp(),clock_timestamp() FROM generate_series(1,20000) i`); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		key, status, billing string
		recovery             any
	}{
		{"manual", "reconcile", "manual", `{}`}, {"decision", "reconcile", "decision_pending", `{}`},
		{"sent", "reconcile", "inflight", `{}`}, {"admitted", "reconcile", "admitted", `{}`},
		{"prepared", "running", "preparing", nil}, {"resolved", "completed", "resolved", `{}`},
		{"unsent-legacy", "failed", "", nil},
	} {
		if _, err = db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_model_invocation(scope_hash,idempotency_key,fingerprint,status,billing_state,billing_recovery_json,created_at,updated_at) VALUES('indexed-active',?,?,?, ?,?,clock_timestamp(),clock_timestamp())`), row.key, "fp", row.status, row.billing, row.recovery); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = admin.ExecContext(ctx, `ANALYZE platform_model_invocation`); err != nil {
		t.Fatal(err)
	}
	const active = `NOT ((status IN ('completed','failed') AND billing_state IN ('done','resolved')) OR (status='failed' AND billing_state='' AND billing_recovery_json IS NULL AND response_json IS NULL AND invocation_token='' AND preparation_deadline IS NULL))`
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM platform_model_invocation WHERE scope_hash='indexed-active' AND `+active).Scan(&count); err != nil || count != 5 {
		t.Fatal("active/unknown records lost or closed records included", count, err)
	}
	for _, item := range []struct{ query, index string }{
		{`SELECT count(*) FROM platform_model_invocation WHERE ` + active, "idx_model_invocation_unsettled"},
		{`SELECT scope_hash FROM platform_model_invocation WHERE billing_state='resolved' ORDER BY updated_at DESC LIMIT 100`, "idx_model_invocation_billing_tail"},
		{`SELECT scope_hash FROM platform_model_invocation WHERE billing_state IN ('manual','decision_pending') ORDER BY updated_at DESC LIMIT 10001`, "idx_model_invocation_billing_tail"},
	} {
		var plan string
		if err = db.QueryRowContext(ctx, "EXPLAIN (FORMAT JSON) "+item.query).Scan(&plan); err != nil || !strings.Contains(plan, item.index) {
			t.Fatal("closed history is still scanned", item.index, err, plan)
		}
	}
	runtimeModels, _ := NewSQLModelInvocationStore(db)
	listed, err := runtimeModels.ListBillingManual(ctx)
	owned := 0
	for _, item := range listed {
		if item.ScopeHash == "indexed-active" {
			owned++
		}
	}
	if err != nil || owned != 3 {
		t.Fatal("manual,decision and resolved visibility changed", len(listed), err)
	}
	for _, index := range []string{"idx_model_budget_active", "idx_model_budget_settled_event", "idx_run_tree_budget_active"} {
		var found bool
		if err = db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, index).Scan(&found); err != nil || !found {
			t.Fatal("required shared ledger index missing", index, err)
		}
	}
}
