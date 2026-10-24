package capability

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/usagecost"
)

func TestSQLUnsentProofSurvivesPartialRelease(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, name := range []string{"billing_unsent_accept_fault", "billing_unsent_finish_fault"} {
			if _, err := dropPostgresBillingFault(ctx, db, name); err != nil {
				t.Errorf("unsent fixture cleanup: %v", err)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil || store.EnsureSchema(ctx) != nil {
		t.Fatal("model schema unavailable")
	}
	budgets := usagecost.NewSQLStore(db)
	if err := store.SetModelBudgetClosureReader(budgets); err != nil {
		t.Fatal(err)
	}
	if err := budgets.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("unsent-%d", time.Now().UnixNano())
	scope, fp := fmt.Sprintf("%x", sha256.Sum256([]byte(id))), strings.Repeat("b", 64)
	now := time.Now().UTC()
	request := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: id, Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, RequestID: id, Fingerprint: fp, PriceVersionID: "price", BudgetLimitMicros: 100, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)}
	reservation, err := budgets.Reserve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	attempt, _, err := store.ReserveGoverned(ctx, scope, id, fp)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{modelStore: store, modelBudgets: budgets}
	if err := m.prepareModelSend(ctx, scope, id, fp, reservation, now.Add(time.Minute), attempt.AttemptToken); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_unsent_accept_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'fixture unsent audit fault' USING ERRCODE='P0001'; RETURN NEW; END $fault$; CREATE TRIGGER billing_unsent_accept_fault BEFORE INSERT ON platform_model_billing_decision FOR EACH ROW EXECUTE FUNCTION billing_unsent_accept_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if err := m.abortUnsentModel(ctx, scope, id, fp, reservation, attempt.AttemptToken); err == nil {
		t.Fatal("release accepted without durable proof")
	}
	var state string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&state); err != nil || state != "reconcile" {
		t.Fatal("proof failure released reserved budget")
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_unsent_accept_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_unsent_accept_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_unsent_finish_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.status='applied' THEN RAISE EXCEPTION 'fixture unsent finish fault' USING ERRCODE='P0001'; END IF; RETURN NEW; END $fault$; CREATE TRIGGER billing_unsent_finish_fault BEFORE UPDATE ON platform_model_billing_decision FOR EACH ROW EXECUTE FUNCTION billing_unsent_finish_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if err := m.abortUnsentModel(ctx, scope, id, fp, reservation, attempt.AttemptToken); err == nil {
		t.Fatal("finish failure hidden")
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&state); err != nil || state != "released" {
		t.Fatal("fixture did not exercise partial release")
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&state); err != nil || state != "decision_pending" {
		t.Fatal("partial release lost compensation intent")
	}
	if err := store.CheckModelQuiescence(ctx, scope); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("released budget without applied unsent proof allowed cancellation", err)
	}
	// A contradictory terminal marker in this isolated fixture cannot replace
	// the actual applied decision. Restore it before normal recovery continues.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='failed',billing_state='resolved' WHERE scope_hash=? AND idempotency_key=?`), scope, id); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckModelQuiescence(ctx, scope); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("resolved marker without applied decision allowed cancellation", err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='reconcile',billing_state='decision_pending' WHERE scope_hash=? AND idempotency_key=?`), scope, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_unsent_finish_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_unsent_finish_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLModelInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	restartedBudgets := usagecost.NewSQLStore(reopenedDB)
	if err := reopened.SetModelBudgetClosureReader(restartedBudgets); err != nil {
		t.Fatal(err)
	}
	restarted := &Module{modelStore: reopened, modelBudgets: restartedBudgets}
	restarted.reconcileBilling(ctx)
	restarted.reconcileBilling(ctx)
	if restarted.billingStats.Completed.Load() != 1 || restarted.billingStats.Failed.Load() != 0 {
		t.Fatal("saved unsent proof not replayed once")
	}
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=? AND reservation_id=?`), scope, id, reservation.ReservationID).Scan(&state); err != nil || state != "applied" {
		t.Fatal("unsent audit not completed")
	}
	if err := reopened.CheckModelQuiescence(ctx, scope); err != nil {
		t.Fatal("durably resolved unsent request still blocks cancellation", err)
	}
	replacement, _, err := reopened.ReserveGoverned(ctx, scope, id, fp)
	if err != nil || replacement.AttemptToken == attempt.AttemptToken {
		t.Fatal("confirmed unsent request not safely retryable")
	}
	if err := reopened.CheckModelQuiescence(ctx, scope); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("prior resolved decision allowed an active replacement attempt", err)
	}
	if _, err := store.PersistUnsent(ctx, scope, id, fp, attempt.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("old unsent proof affected new attempt")
	}
	if err := reopened.FailPreparation(ctx, scope, id, fp, replacement.AttemptToken); err != nil {
		t.Fatal("fixture preparation not drained")
	}
}
