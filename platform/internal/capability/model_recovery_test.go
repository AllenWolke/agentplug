package capability

import (
	"context"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/usagecost"
)

func TestBillingRecoveryReplaysKnownResponseWithoutProvider(t *testing.T) {
	budgets := &captureModelBudgetStore{settleErr: errors.New("fixture SQL outage")}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "known answer", InputTokens: 12, OutputTokens: 4}}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	m.SetModelBilling(testApprovedPriceResolver(), budgets)
	m.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "recovery", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	if result := capabilityRequest(t, m, "/internal/model/generate", capabilityContext(), input); result.Code != http.StatusBadGateway {
		t.Fatal("settlement failure was hidden")
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	budgets.settleErr = nil
	// A replacement module consumes saved receipts, not a model gateway.
	// 新模块只消费持久化回执，不装配模型调用端口。
	restarted := &Module{modelStore: store, modelBudgets: budgets}
	restarted.reconcileBilling(context.Background())
	restarted.reconcileBilling(context.Background())
	result := capabilityRequest(t, m, "/internal/model/generate", capabilityContext(), input)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "known answer") || gateway.calls != 1 || restarted.billingStats.Completed.Load() != 1 || len(budgets.settled) != 1 {
		t.Fatal("saved response did not replay without a second model charge")
	}
	if strings.Contains(result.Body.String(), "reservation_id") {
		t.Fatal("internal recovery envelope leaked to caller")
	}
}

func TestBillingWorkerLifecycleAndUnknownOutcomeNotAutoSettled(t *testing.T) {
	store := newMemoryModelInvocationStore()
	if _, _, err := store.Reserve(context.Background(), "scope", "known", "fp", 0, 0); err != nil {
		t.Fatal(err)
	}
	event := usagecost.Event{ID: "event"}
	intent := BillingRecovery{Reservation: usagecost.ModelBudgetReservation{PriceVersionID: "price"}, Event: &event, PriceID: "price"}
	if err := store.SaveBillingRecovery(context.Background(), "scope", "known", "fp", map[string]any{"text": "saved"}, 1, intent); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Reserve(context.Background(), "scope", "unknown", "fp", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBillingRecovery(context.Background(), "scope", "unknown", "fp", nil, 0, BillingRecovery{}); err != nil {
		t.Fatal(err)
	}
	m := &Module{modelStore: store, modelBudgets: &captureModelBudgetStore{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for m.billingStats.Completed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := m.Close(closeCtx); err != nil || m.billingStats.Completed.Load() != 1 {
		t.Fatal("real module worker lifecycle did not drain")
	}
	store.mu.Lock()
	unknown := store.records["scope\x00unknown"]
	store.mu.Unlock()
	if unknown.Status != "reconcile" || unknown.Response != nil {
		t.Fatal("unknown provider outcome was silently released or settled")
	}
}

// Isolated PostgreSQL proves persistent retry after actual settlement write faults.
// 隔离真实 PostgreSQL 故障验证：预算保留、重连补账与准确一次结果回放。
func TestSQLBillingRecoveryRetainsHoldAndReplaysAfterRestart(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := NewSQLModelInvocationStore(db)
	if err != nil || store.EnsureSchema(ctx) != nil {
		t.Fatal("model schema unavailable")
	}
	budgets := usagecost.NewSQLStore(db)
	if err := budgets.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("billing-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	scopeHash := strings.Repeat("a", 64)
	fingerprint := strings.Repeat("b", 64)
	request := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "department", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: "run-" + id, Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, RequestID: id, Fingerprint: fingerprint, PriceVersionID: "price-v1", BudgetLimitMicros: 100, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)}
	reservation, err := budgets.Reserve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Reserve(ctx, scopeHash, id, fingerprint, 0, 0); err != nil {
		t.Fatal(err)
	}
	event := usagecost.Event{ID: "event-" + id, Scope: usagecost.Scope{TenantID: id, DepartmentID: "department", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1", RunID: request.RunID}, Provider: "fixture", Model: "fixture", InputTokens: 12, OutputTokens: 4, CostMicros: 60}
	response := map[string]any{"text": "saved response"}
	if err := budgets.MarkReconciliationNeeded(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveBillingRecovery(ctx, scopeHash, id, fingerprint, response, 1, BillingRecovery{Reservation: reservation, Event: &event, PriceID: request.PriceVersionID}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_settlement_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'fixture fault' USING ERRCODE='P0001'; RETURN NEW; END $fault$; CREATE TRIGGER billing_settlement_fault BEFORE INSERT ON platform_usage_event FOR EACH ROW EXECUTE FUNCTION billing_settlement_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP TRIGGER IF EXISTS billing_settlement_fault ON platform_usage_event; DROP FUNCTION IF EXISTS billing_settlement_fault_fn()`)
	m := &Module{modelStore: store, modelBudgets: budgets}
	m.reconcileBilling(ctx)
	var state string
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&state); err != nil || state != "reconcile" || m.billingStats.Failed.Load() != 1 {
		t.Fatal("failed settlement released budget or lost failure signal")
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_settlement_fault ON platform_usage_event; DROP FUNCTION IF EXISTS billing_settlement_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_retry_at=NULL WHERE scope_hash=? AND idempotency_key=?`), scopeHash, id); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, _ := NewSQLModelInvocationStore(reopenedDB)
	restarted := &Module{modelStore: reopened, modelBudgets: usagecost.NewSQLStore(reopenedDB)}
	// Settlement may commit while completing the replay ledger fails.
	// 结算已提交但回放账本终结失败时，仍只能补账本，不能重复消费模型。
	if _, err := reopenedDB.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_completion_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.status='completed' THEN RAISE EXCEPTION 'fixture completion fault' USING ERRCODE='P0001'; END IF; RETURN NEW; END $fault$; CREATE TRIGGER billing_completion_fault BEFORE UPDATE ON platform_model_invocation FOR EACH ROW EXECUTE FUNCTION billing_completion_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Exec(`DROP TRIGGER IF EXISTS billing_completion_fault ON platform_model_invocation; DROP FUNCTION IF EXISTS billing_completion_fault_fn()`)
	restarted.reconcileBilling(ctx)
	if restarted.billingStats.Failed.Load() != 1 {
		t.Fatal("completion write failure was hidden")
	}
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&state); err != nil || state != "settled" {
		t.Fatal("settled budget incorrectly reopened on ledger failure")
	}
	if _, err := reopenedDB.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_completion_fault ON platform_model_invocation; DROP FUNCTION IF EXISTS billing_completion_fault_fn()`)); err != nil {
		t.Fatal(err)
	}
	if _, err := reopenedDB.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_retry_at=NULL WHERE scope_hash=? AND idempotency_key=?`), scopeHash, id); err != nil {
		t.Fatal(err)
	}
	restarted.reconcileBilling(ctx)
	restarted.reconcileBilling(ctx)
	replayed, replay, err := reopened.Reserve(ctx, scopeHash, id, fingerprint, 0, 0)
	if err != nil || !replay || replayed.Response["text"] != "saved response" || restarted.billingStats.Completed.Load() != 1 {
		t.Fatal("saved result not recovered after DB reconnect")
	}
	var count int
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_event WHERE event_id=?`), event.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("reconciliation duplicated usage event")
	}
	if err := reopened.Complete(ctx, scopeHash, id, fingerprint, response, 1); err != nil {
		t.Fatal("identical completion replay rejected")
	}
	if err := reopened.Complete(ctx, scopeHash, id, fingerprint, map[string]any{"text": "tampered"}, 1); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("different completed response accepted")
	}
}
