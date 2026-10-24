package capability

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type preparedAckLostStore struct{ *memoryModelInvocationStore }

type firstPreparedAckLostStore struct {
	*memoryModelInvocationStore
	saves int
}

func (s *firstPreparedAckLostStore) SaveBillingRecovery(ctx context.Context, scope, key, fp string, response map[string]any, cost int64, recovery BillingRecovery) error {
	if err := s.memoryModelInvocationStore.SaveBillingRecovery(ctx, scope, key, fp, response, cost, recovery); err != nil {
		return err
	}
	s.saves++
	if s.saves == 1 {
		return context.Canceled
	}
	return nil
}

func TestPreDispatchReturnRoutingAcceptsExactProofAndKeepsWinner(t *testing.T) {
	m, op, gateway, budget := resilientInvocationFixture(t)
	store := m.modelStore.(*memoryModelInvocationStore)
	m.modelStore = &firstPreparedAckLostStore{memoryModelInvocationStore: store}
	response := invokeFailover(m, op, context.Background())
	if response.Code != http.StatusOK || len(gateway.calls) != 1 || len(budget.released) != 1 || len(budget.settled) != 1 {
		t.Fatal("closed pre-dispatch failure did not use one authorized alternate", response.Code, response.Body.String())
	}
	state, found, err := store.LookupModelRouteExecution(context.Background(), modelSelectionScopeHash(scopeFromHarness(op.Context)), "logical-call")
	if err != nil || !found || len(state.Steps) != 2 || state.Steps[0].Disposition != "unsent" || state.Status != "completed" {
		t.Fatal("route disposition lost the exact owner-returned proof", state, err)
	}
	response = invokeFailover(m, op, context.Background())
	if response.Code != http.StatusOK || len(gateway.calls) != 1 || len(budget.settled) != 1 {
		t.Fatal("route replay resent an original or alternate")
	}
}

func (s *preparedAckLostStore) SaveBillingRecovery(ctx context.Context, scope, key, fp string, response map[string]any, cost int64, recovery BillingRecovery) error {
	if err := s.memoryModelInvocationStore.SaveBillingRecovery(ctx, scope, key, fp, response, cost, recovery); err != nil {
		return err
	}
	return context.Canceled // Durable prepared state exists; dispatch was never attempted.
}

func TestPreDispatchReturnClosesLostPreparationAckBeforeExpiry(t *testing.T) {
	budgets := &captureModelBudgetStore{}
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	store := m.modelStore.(*memoryModelInvocationStore)
	m.modelStore = &preparedAckLostStore{store}
	gateway := &captureModelGateway{result: modelgateway.GenerateResult{Text: "unused"}}
	m.SetGovernedModelInvocation(fixedModelAccess(), gateway)
	m.SetModelBilling(testApprovedPriceResolver(), budgets)
	m.SetModelCapacity(&captureModelCapacity{})
	r := capabilityRequest(t, m, "/internal/model/generate", capabilityContext(), map[string]any{
		"idempotency_key": "lost-preparation-ack", "prompt_template_hash": "prompt-hash",
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	if r.Code != http.StatusServiceUnavailable || gateway.calls != 0 || len(budgets.released) != 1 {
		t.Fatal("lost pre-dispatch acknowledgement leaked a hold or sent the provider", r.Code, gateway.calls, len(budgets.released))
	}
	record, err := store.GetBillingRecord(context.Background(), capabilityScopeHash(capabilityContext()), "lost-preparation-ack")
	if err != nil || record.Status != "failed" || record.Recovery == nil || record.Recovery.Decision == nil || !strings.HasPrefix(record.Recovery.Decision.ID, "returned-") {
		t.Fatal("original failed preparation has no durable owner-returned proof", err)
	}
}

func TestPreDispatchReturnRejectsSentResultAndStaleOwner(t *testing.T) {
	for _, name := range []string{"prepared", "admitted", "dispatching", "response", "stale-owner"} {
		t.Run(name, func(t *testing.T) {
			s := newMemoryModelInvocationStore()
			r, _, err := s.ReserveGoverned(context.Background(), "scope", name, "fp")
			if err != nil {
				t.Fatal(err)
			}
			recovery := BillingRecovery{AttemptToken: r.AttemptToken, PriceID: "price", SendPhase: "prepared", SendDeadline: time.Now().Add(2 * time.Minute),
				Reservation: usagecost.ModelBudgetReservation{ReservationID: "original", Scope: usagecost.ModelBudgetScope{TenantID: "tenant"}}}
			if name == "admitted" {
				recovery.SendPhase, recovery.SendDeadline, recovery.AdmissionUntil = "", time.Time{}, time.Now().Add(2*time.Minute)
			}
			if name == "dispatching" {
				recovery.SendPhase = "dispatching"
			}
			r.Status, r.Recovery = "reconcile", &recovery
			if name == "response" {
				r.Response = map[string]any{"text": "known result"}
			}
			s.records["scope\x00"+name] = r
			token := r.AttemptToken
			if name == "stale-owner" {
				token = "another-owner"
			}
			_, err = s.PersistPreDispatchReturn(context.Background(), "scope", name, "fp", token)
			if name == "prepared" || name == "admitted" {
				if err != nil {
					t.Fatal("owning return waited for preparation expiry", err)
				}
			} else if !errors.Is(err, ErrModelInvocationConflict) {
				t.Fatal("unsafe no-send proof accepted", err)
			}
		})
	}
}

func TestSQLPreDispatchReturnCompetesWithDispatchAndClosesOriginalHold(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := NewSQLModelInvocationStore(db)
	b := usagecost.NewSQLStore(db)
	if err = s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = b.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 8; iteration++ {
		id := fmt.Sprintf("returned-%d-%d", time.Now().UnixNano(), iteration)
		hash, fp := strings.Repeat("a", 64), strings.Repeat("b", 64)
		now := time.Now().UTC()
		r, err := b.Reserve(ctx, usagecost.ModelBudgetRequest{Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "dept", ApplicationID: "app", AgentID: "qa", AgentVersionID: "v1"}, RunID: id,
			Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, RequestID: id, Fingerprint: fp,
			PriceVersionID: "price", BudgetLimitMicros: 1000, ReserveMicros: 80, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := s.ReserveGoverned(ctx, hash, id, fp)
		if err != nil {
			t.Fatal(err)
		}
		m := &Module{modelStore: s, modelBudgets: b}
		if iteration == 0 {
			tx, txErr := db.BeginTx(ctx, nil)
			if txErr != nil {
				t.Fatal(txErr)
			}
			bound := withModelBudgetPreparation(ctx, hash, id, fp, owner.AttemptToken)
			if txErr = s.RecordBudgetAdmissionTx(bound, tx, r); txErr != nil {
				tx.Rollback()
				t.Fatal(txErr)
			}
			if txErr = tx.Commit(); txErr != nil {
				t.Fatal(txErr)
			}
			cancelled, stop := context.WithCancel(ctx)
			stop()
			m.closePreDispatchReturn(cancelled, hash, id, fp, owner.AttemptToken, "fixture")
			var status string
			if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), r.ReservationID).Scan(&status); err != nil || status != "released" {
				t.Fatal("cancelled owner retained live admitted hold until expiry", status, err)
			}
			continue
		}
		if err = m.prepareModelSend(ctx, hash, id, fp, r, now.Add(time.Minute), owner.AttemptToken); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var dispatchErr, returnErr error
		var closed ModelInvocation
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			dispatchErr = s.BeginModelDispatch(ctx, hash, id, fp, owner.AttemptToken)
		}()
		go func() {
			defer wg.Done()
			<-start
			closed, returnErr = s.PersistPreDispatchReturn(ctx, hash, id, fp, owner.AttemptToken)
		}()
		close(start)
		wg.Wait()
		if (dispatchErr == nil) == (returnErr == nil) {
			t.Fatal("dispatch and no-send proof did not have exactly one winner", dispatchErr, returnErr)
		}
		if returnErr == nil {
			if err = b.ResolveUncharged(ctx, r, closed.Recovery.Decision.ProviderRef); err != nil {
				t.Fatal(err)
			}
			if err = s.FinishUnsent(ctx, closed); err != nil {
				t.Fatal(err)
			}
		} else {
			if !errors.Is(returnErr, ErrModelInvocationConflict) {
				t.Fatal(returnErr)
			}
			// This fixture never calls a provider. Its trusted adapter no-send
			// proof cleans up the winning dispatch; production unknowns retain it.
			if err = m.abortUnsentModel(ctx, hash, id, fp, r, owner.AttemptToken); err != nil {
				t.Fatal(err)
			}
		}
		var status string
		if err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status FROM platform_model_budget_reservation WHERE reservation_id=?`), r.ReservationID).Scan(&status); err != nil || status != "released" {
			t.Fatal("original reservation not closed exactly", status, err)
		}
	}
}
