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

type failPreparedModelStore struct{ *memoryModelInvocationStore }

func (s *failPreparedModelStore) SaveBillingRecovery(context.Context, string, string, string, map[string]any, int64, BillingRecovery) error {
	return errors.New("fixture persistence failure")
}

func TestModelRecoveryEnvelopeExistsBeforeGenerate(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		budgets := &captureModelBudgetStore{}
		m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
		store := m.modelStore.(*memoryModelInvocationStore)
		if failSave {
			m.modelStore = &failPreparedModelStore{store}
		}
		gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "answer", InputTokens: 1, OutputTokens: 1}}
		gateway.before = func() {
			store.mu.Lock()
			defer store.mu.Unlock()
			record := store.records[capabilityScopeHash(capabilityContext())+"\x00prepared-observer"]
			if record.Status != "reconcile" || record.Recovery == nil || record.Recovery.SendPhase != "dispatching" || !record.Recovery.SendDeadline.After(time.Now()) || len(budgets.reconciled) != 1 {
				t.Fatal("generation sent before persisted retained intent")
			}
		}
		m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
		m.SetModelBilling(testApprovedPriceResolver(), budgets)
		m.SetModelCapacity(&captureModelCapacity{})
		result := capabilityRequest(t, m, "/internal/model/generate", capabilityContext(), map[string]any{"idempotency_key": "prepared-observer", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}})
		if failSave {
			if result.Code != http.StatusServiceUnavailable || gateway.calls != 0 {
				t.Fatal("persistence failure sent generation")
			}
		} else if result.Code != http.StatusOK || gateway.calls != 1 {
			t.Fatal("prepared call failed")
		}
	}
}

func TestModelSendHoldFailureNeverInvokesProvider(t *testing.T) {
	budgets := &captureModelBudgetStore{holdErr: errors.New("fixture hold failure")}
	gateway := &captureModelGateway{}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	m.SetModelBilling(testApprovedPriceResolver(), budgets)
	m.SetModelCapacity(&captureModelCapacity{})
	input := map[string]any{"idempotency_key": "hold-fault", "prompt_template_hash": "prompt-hash", "messages": []map[string]string{{"role": "user", "content": "hello"}}}
	result := capabilityRequest(t, m, "/internal/model/generate", capabilityContext(), input)
	if result.Code != http.StatusServiceUnavailable || !strings.Contains(result.Body.String(), "MODEL_SEND_PERSISTENCE_FAILED") || gateway.calls != 0 {
		t.Fatal("provider called without durable budget hold")
	}
	store := m.modelStore.(*memoryModelInvocationStore)
	store.mu.Lock()
	record := cloneInvocation(store.records[capabilityScopeHash(capabilityContext())+"\x00hold-fault"])
	store.mu.Unlock()
	if record.Status != "reconcile" || record.Recovery == nil || record.Recovery.Reservation.ReservationID == "" || record.Recovery.Decision == nil || record.Recovery.Decision.Outcome != "no_charge" || record.Response != nil || len(budgets.released) != 0 {
		t.Fatal("persistent hold-store failure lost the original unsent proof or released without accounting")
	}
	m.reconcileBilling(context.Background())
	if m.billingStats.Completed.Load() != 0 {
		t.Fatal("already closed attempt was reconciled again")
	}
}

// Reopen SQL after a dispatched attempt with no result; never generate on recovery.
// 已进入发送边界的请求没有结果时重连数据库恢复，只转核对，禁止重跑模型。
func TestSQLPreparedModelSendSurvivesTTLAndReopen(t *testing.T) {
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
	id := fmt.Sprintf("prepared-%d", time.Now().UnixNano())
	scope, fp := strings.Repeat("a", 64), strings.Repeat("b", 64)
	now := time.Now().UTC()
	request := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: "run-" + id, Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, RequestID: id, Fingerprint: fp, PriceVersionID: "price", BudgetLimitMicros: 100, ReserveMicros: 80, ExpiresAt: now.Add(time.Second)}
	reservation, err := budgets.Reserve(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, _, err := store.ReserveGoverned(ctx, scope, id, fp)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{modelStore: store, modelBudgets: budgets}
	if err := m.prepareModelSend(ctx, scope, id, fp, reservation, now.Add(2*time.Second), prepared.AttemptToken); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginModelDispatch(ctx, scope, id, fp, prepared.AttemptToken); err != nil {
		t.Fatal(err)
	}
	views, err := store.ListBillingManual(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.Key == id {
			t.Fatal("live send exposed as manual")
		}
	}
	decision := BillingDecision{ID: "early", ReservationID: reservation.ReservationID, ActorID: "admin", ActorTenant: "tenant", Outcome: "no_charge", Reason: "fixture", ProviderRef: "fixture"}
	if err := store.AcceptBillingDecision(ctx, scope, id, fp, decision); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("active call released by manual decision")
	}
	time.Sleep(2200 * time.Millisecond)
	reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened, err := NewSQLModelInvocationStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &Module{modelStore: reopened, modelBudgets: usagecost.NewSQLStore(reopenedDB)}
	restarted.reconcileBilling(ctx)
	restarted.reconcileBilling(ctx)
	var status string
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&status); err != nil || status != "reconcile" {
		t.Fatal("TTL released unknown provider outcome")
	}
	var state string
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&state); err != nil || state != "manual" || restarted.billingStats.Completed.Load() != 1 {
		t.Fatal("prepared call not recovered to manual once")
	}
	if _, _, err := reopened.Reserve(ctx, scope, id, fp, 0, 0); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
		t.Fatal("restart allowed duplicate model generation")
	}
	request.RequestID = id + "-second"
	request.ExpiresAt = time.Now().UTC().Add(time.Minute)
	if _, err := restarted.modelBudgets.Reserve(ctx, request); !errors.Is(err, usagecost.ErrBudgetExceeded) {
		t.Fatal("unknown hold did not consume budget after TTL")
	}
	if err := reopened.AcceptBillingDecision(ctx, scope, id, fp, decision); err != nil {
		t.Fatal("expired attempt could not be explicitly reconciled")
	}
	// Finish the fixture intent so repeated full suites cannot consume its work.
	// 完成夹具意图，避免整组复跑的其他测试消费本用例留下的待办。
	restarted.reconcileBilling(ctx)
	if err := reopenedDB.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=? AND reservation_id=?`), scope, id, reservation.ReservationID).Scan(&state); err != nil || state != "applied" {
		t.Fatal("fixture manual decision not fully drained")
	}
}
