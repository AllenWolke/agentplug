package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/usagecost"
)

type billingAdminFixture struct {
	*memoryModelInvocationStore
	calls    int
	decision BillingDecision
}

func (s *billingAdminFixture) GetBillingRecord(context.Context, string, string) (ModelInvocation, error) {
	return ModelInvocation{}, nil
}
func (s *billingAdminFixture) AcceptBillingDecision(_ context.Context, _, _, _ string, d BillingDecision) error {
	s.calls++
	s.decision = d
	return nil
}
func (s *billingAdminFixture) FinishBillingDecision(context.Context, ModelInvocation) error {
	return nil
}
func (s *billingAdminFixture) ListBillingManual(context.Context) ([]BillingRecordView, error) {
	return []BillingRecordView{}, nil
}

type billingControlFixture struct{ err error }

func (f billingControlFixture) AuthorizeModelGovernance(_ context.Context, a modelgovernance.Actor, action modelgovernance.Action, target modelgovernance.Scope) error {
	if a.PrincipalID != "admin" || action != modelgovernance.ActionApprove || !target.IsGlobal() {
		return modelgovernance.ErrForbidden
	}
	return f.err
}

func TestManualChargedDecisionCarriesReservationBoundModelStepID(t *testing.T) {
	reservation := usagecost.ModelBudgetReservation{
		ReservationID: "reservation", RequestID: "model-request-key", RunID: "run-1",
		Scope: usagecost.ModelBudgetScope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1"},
	}
	record := ModelInvocation{Status: "reconcile", Recovery: &BillingRecovery{Reservation: reservation, PriceID: "price-v1"}}
	decision := BillingDecision{ID: "decision", ReservationID: reservation.ReservationID, ActorID: "admin", ActorTenant: "tenant", Outcome: "charged", Reason: "provider charge confirmed", ProviderRef: "receipt", Provider: "provider", Model: "model", InputTokens: 3, OutputTokens: 2, CostMicros: 5}
	intent, err := decisionIntent(record, decision)
	if err != nil || intent.Event == nil {
		t.Fatalf("charged decision did not produce usage evidence: intent=%+v err=%v", intent, err)
	}
	scope := usagecost.Scope{TenantID: reservation.Scope.TenantID, DepartmentID: reservation.Scope.DepartmentID, ApplicationID: reservation.Scope.ApplicationID, AgentID: reservation.Scope.AgentID, AgentVersionID: reservation.Scope.AgentVersionID, RunID: reservation.RunID}
	want := usagecost.StableModelUsageStepID(scope, reservation.RequestID)
	if want == nil || intent.Event.StepID == nil || *intent.Event.StepID != *want {
		t.Fatalf("manual usage must retain the original request step ID: got=%v want=%v", intent.Event.StepID, want)
	}
}

func TestBillingAdminRejectsForgedIdentityAndInvalidInput(t *testing.T) {
	store := &billingAdminFixture{memoryModelInvocationStore: newMemoryModelInvocationStore()}
	m := &Module{internalToken: "internal", modelStore: store, billingControl: billingControlFixture{}}
	body := `{"scope_hash":"` + strings.Repeat("a", 64) + `","idempotency_key":"call","fingerprint":"` + strings.Repeat("b", 64) + `","decision":{"id":"decision","reservation_id":"reservation","outcome":"no_charge","reason":"provider confirmed","provider_ref":"receipt"}}`
	request := func(body, principal, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/billing/reconciliations", strings.NewReader(body))
		r.Header.Set("X-Internal-Token", token)
		r.Header.Set("X-Browser-Module", "1")
		r.Header.Set("X-Tenant-ID", "tenant")
		r.Header.Set("X-Principal-Type", "user")
		r.Header.Set("X-Principal-ID", principal)
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		return w
	}
	if request(body, "admin", "wrong").Code != http.StatusUnauthorized || request(body, "ordinary-user", "internal").Code != http.StatusForbidden || store.calls != 0 {
		t.Fatal("unauthorized billing decision had effects")
	}
	for _, broken := range []string{"{", body + "{}", strings.Replace(body, `"decision":{"id"`, `"decision":{"actor_id":"forged","id"`, 1)} {
		if request(broken, "admin", "internal").Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatal("invalid request accepted")
		}
	}
	if request(body, "admin", "internal").Code != http.StatusOK || store.calls != 1 || store.decision.ActorID != "admin" || store.decision.ActorTenant != "tenant" {
		t.Fatal("trusted actor not projected")
	}
}

// Real SQL proves decision audit atomicity and compensation without model retries.
// 真实SQL验证人工决策审计原子性及故障恢复，恢复不得再次调用模型。
func TestSQLBillingManualDecisionAuditAndCompensation(t *testing.T) {
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
		cleanupCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		for _, name := range []string{"billing_audit_accept_fault", "billing_audit_apply_fault"} {
			if _, err := dropPostgresBillingFault(cleanupCtx, db, name); err != nil {
				t.Errorf("billing fixture trigger cleanup failed: %v", err)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, _ := NewSQLModelInvocationStore(db)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	budgets := usagecost.NewSQLStore(db)
	if err := budgets.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"no_charge", "charged"} {
		t.Run(outcome, func(t *testing.T) {
			id := fmt.Sprintf("manual-%s-%d", outcome, time.Now().UnixNano())
			// Each fixture owns its invocation scope. A safely retryable no-charge
			// case ends by reserving another attempt; another suite must not query
			// that intentionally pending attempt as if it belonged to its own Run.
			digest := sha256.Sum256([]byte(id))
			scope := hex.EncodeToString(digest[:])
			fp := strings.Repeat("d", 64)
			now := time.Now().UTC()
			req := usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: "run-" + id, Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, RequestID: id, Fingerprint: fp, PriceVersionID: "price", BudgetLimitMicros: 100, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)}
			reservation, err := budgets.Reserve(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Reserve(ctx, scope, id, fp, 0, 0); err != nil {
				t.Fatal(err)
			}
			if err := budgets.MarkReconciliationNeeded(ctx, reservation); err != nil {
				t.Fatal(err)
			}
			if err := store.SaveBillingRecovery(ctx, scope, id, fp, nil, 0, BillingRecovery{Reservation: reservation, PriceID: req.PriceVersionID}); err != nil {
				t.Fatal(err)
			}
			d := BillingDecision{ID: "decision", ReservationID: reservation.ReservationID, ActorID: "admin", ActorTenant: "admin-tenant", Outcome: outcome, Reason: "confirmed in provider billing", ProviderRef: "provider-receipt-" + id}
			if outcome == "charged" {
				d.Provider = "provider"
				d.Model = "model"
				d.CostMicros = 60
				d.InputTokens = 12
				d.OutputTokens = 4
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_audit_accept_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RAISE EXCEPTION 'fixture audit fault' USING ERRCODE='P0001'; RETURN NEW; END $fault$; CREATE TRIGGER billing_audit_accept_fault BEFORE INSERT ON platform_model_billing_decision FOR EACH ROW EXECUTE FUNCTION billing_audit_accept_fault_fn()`)); err != nil {
				t.Fatal(err)
			}
			if err := store.AcceptBillingDecision(ctx, scope, id, fp, d); err == nil {
				t.Fatal("missing audit accepted decision")
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_audit_accept_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_audit_accept_fault_fn()`)); err != nil {
				t.Fatal(err)
			}
			var state string
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&state); err != nil || state != "manual" {
				t.Fatal("decision/audit not atomic")
			}
			var wg sync.WaitGroup
			failures := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := store.AcceptBillingDecision(ctx, scope, id, fp, d); err != nil {
						failures <- err
					}
				}()
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Fatal(err)
			}
			changed := d
			changed.ProviderRef = "different"
			if err := store.AcceptBillingDecision(ctx, scope, id, fp, changed); !errors.Is(err, ErrModelInvocationConflict) {
				t.Fatal("different decision replay accepted")
			}
			var count int
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&count); err != nil || count != 1 {
				t.Fatal("concurrent approval audit duplicated")
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION billing_audit_apply_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.status='applied' THEN RAISE EXCEPTION 'fixture audit fault' USING ERRCODE='P0001'; END IF; RETURN NEW; END $fault$; CREATE TRIGGER billing_audit_apply_fault BEFORE UPDATE ON platform_model_billing_decision FOR EACH ROW EXECUTE FUNCTION billing_audit_apply_fault_fn()`)); err != nil {
				t.Fatal(err)
			}
			m := &Module{modelStore: store, modelBudgets: budgets}
			m.reconcileBilling(ctx)
			if m.billingStats.Failed.Load() != 1 {
				t.Fatal("audit completion failure hidden")
			}
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT billing_state FROM platform_model_invocation WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&state); err != nil || state != "decision_pending" {
				t.Fatal("completion/audit not atomic")
			}
			if err := store.CheckModelQuiescence(ctx, scope); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
				t.Fatal("partial settlement without applied audit allowed cancellation", err)
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER billing_audit_apply_fault ON platform_model_billing_decision; DROP FUNCTION IF EXISTS billing_audit_apply_fault_fn()`)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET billing_retry_at=NULL WHERE scope_hash=? AND idempotency_key=?`), scope, id); err != nil {
				t.Fatal(err)
			}
			reopenedDB, err := sqlutil.OpenPostgres(context.Background(), dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer reopenedDB.Close()
			reopened, _ := NewSQLModelInvocationStore(reopenedDB)
			restarted := &Module{modelStore: reopened, modelBudgets: usagecost.NewSQLStore(reopenedDB)}
			restarted.reconcileBilling(ctx)
			restarted.reconcileBilling(ctx)
			if restarted.billingStats.Completed.Load() != 1 {
				t.Fatal("manual compensation did not complete once")
			}
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_billing_decision WHERE scope_hash=? AND idempotency_key=?`), scope, id).Scan(&state); err != nil || state != "applied" {
				t.Fatal("audit did not recover")
			}
			if err := reopened.CheckModelQuiescence(ctx, scope); err != nil {
				t.Fatal("applied decision and closed budget still block cancellation", err)
			}
			if outcome == "charged" {
				if _, _, err := reopened.Reserve(ctx, scope, id, fp, 0, 0); !errors.Is(err, ErrModelInvocationReconciliationNeeded) {
					t.Fatal("paid unknown answer permitted duplicate model generation")
				}
			} else {
				if _, replay, err := reopened.Reserve(ctx, scope, id, fp, 0, 0); err != nil || replay {
					t.Fatal("confirmed no charge cannot retry safely")
				}
				if err := reopened.AcceptBillingDecision(ctx, scope, id, fp, d); err == nil {
					t.Fatal("old receipt applied to a new model attempt")
				}
			}
		})
	}
}
