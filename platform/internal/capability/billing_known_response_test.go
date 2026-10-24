package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/modelgovernance"
	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/lexagent/platform/internal/usagecost"
)

type knownBillingCatalogFixture struct {
	*fixedModelPriceResolver
	model modelgovernance.ResolvedModel
}

func (c *knownBillingCatalogFixture) GetPriceVersion(_ context.Context, id string) (modelgovernance.PriceVersion, error) {
	if id != c.price.ID {
		return modelgovernance.PriceVersion{}, modelgovernance.ErrNotFound
	}
	return c.price, nil
}
func (c *knownBillingCatalogFixture) GetResolvedVersion(_ context.Context, id string) (modelgovernance.ResolvedModel, error) {
	if id != c.model.VersionID {
		return modelgovernance.ResolvedModel{}, modelgovernance.ErrNotFound
	}
	return c.model, nil
}

func knownBillingFixture(t *testing.T) (*Module, ModelInvocation, *knownBillingCatalogFixture, *captureModelBudgetStore) {
	t.Helper()
	ctx := context.Background()
	store := newMemoryModelInvocationStore()
	scope, key, fp := strings.Repeat("a", 64), "original-model-key", strings.Repeat("b", 64)
	r, _, err := store.ReserveGoverned(ctx, scope, key, fp)
	if err != nil {
		t.Fatal(err)
	}
	reservation := usagecost.ModelBudgetReservation{ReservationID: "original-reservation", Scope: usagecost.ModelBudgetScope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1"}, RunID: "original-run", RequestID: "distinct-attempt-request", Fingerprint: fp, PriceVersionID: "original-price"}
	response := map[string]any{"provider_id": "provider-id", "model_id": "definition-id", "model_version_id": "version-id", "model": "approved-model-alias", "text": "authentic saved output", "usage": map[string]int{"input_tokens": 239, "output_tokens": 23}}
	if err := store.SaveBillingRecovery(ctx, scope, key, fp, response, 0, BillingRecovery{Reservation: reservation, PriceID: reservation.PriceVersionID, AttemptToken: r.AttemptToken}); err != nil {
		t.Fatal(err)
	}
	// Ordinary receipt reads deliberately hide unsettled responses. The
	// authenticated billing store reads the saved internal record in full.
	store.mu.Lock()
	record := store.records[scope+"\x00"+key]
	store.mu.Unlock()
	record.Response = cloneMap(record.Response)
	rawRecovery, err := json.Marshal(record.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawRecovery, &record.Recovery); err != nil {
		t.Fatal(err)
	}
	rate := int64(0)
	catalog := &knownBillingCatalogFixture{fixedModelPriceResolver: &fixedModelPriceResolver{price: modelgovernance.PriceVersion{ID: "original-price", ModelVersionID: "version-id", Currency: "USD", Status: "approved", CachedInputMicrosPer1K: &rate}}, model: modelgovernance.ResolvedModel{VersionID: "version-id", DefinitionID: "definition-id", ProviderID: "provider-id", ProviderKey: "approved-provider", ModelKey: "approved-model-alias", Kind: "chat", VersionStatus: "approved", ProviderStatus: "approved"}}
	budgets := &captureModelBudgetStore{}
	return &Module{modelStore: store, modelPrices: catalog, modelBudgets: budgets}, record, catalog, budgets
}

func TestKnownResponseRecoverySettlesOriginalMeasuredTokensWithoutProviderOrInventedCacheHit(t *testing.T) {
	m, record, _, budgets := knownBillingFixture(t)
	if err := m.resumeKnownBilling(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	m.reconcileBilling(context.Background())
	m.reconcileBilling(context.Background())
	got, found, err := m.modelStore.(modelReceiptReadStore).LookupModelInvocation(context.Background(), record.ScopeHash, record.Key)
	if err != nil || !found || got.Status != "completed" || budgets.settleCalls != 1 || len(budgets.settled) != 1 {
		t.Fatal("original response did not settle once", got.Status, err, budgets.settleCalls)
	}
	event := budgets.settled[0]
	if event.InputTokens != 239 || event.OutputTokens != 23 || event.CostMicros != 0 || event.Scope.RunID != "original-run" {
		t.Fatal("usage was guessed or moved", event)
	}
	usage := got.Response["usage"].(map[string]any)
	if _, invented := usage["cached_input_tokens"]; invented || got.Response["billing"].(map[string]any)["cache_usage_known"] != false {
		t.Fatal("unreported cache split fabricated")
	}
	if m.modelGateway != nil {
		t.Fatal("recovery unexpectedly needs provider")
	}
}

func TestKnownResponseRecoveryRejectsMissingDifferentialOrConflictingEvidence(t *testing.T) {
	for _, mode := range []string{"missing-response", "differential", "fractional-token", "missing-token", "foreign-model", "foreign-price", "fingerprint", "unsent", "revoked-price", "partial-cache-split"} {
		t.Run(mode, func(t *testing.T) {
			m, record, catalog, budgets := knownBillingFixture(t)
			switch mode {
			case "missing-response":
				record.Response = nil
			case "differential":
				catalog.price.InputMicrosPer1K = 100
			case "fractional-token":
				record.Response["usage"].(map[string]any)["input_tokens"] = 239.5
			case "missing-token":
				delete(record.Response["usage"].(map[string]any), "input_tokens")
			case "partial-cache-split":
				record.Response["usage"].(map[string]any)["uncached_input_tokens"] = 239
			case "foreign-model":
				record.Response["model_id"] = "foreign"
			case "foreign-price":
				record.Recovery.PriceID = "different-price"
			case "fingerprint":
				record.Recovery.Reservation.Fingerprint = "changed"
			case "unsent":
				record.Recovery.Unsent = true
			case "revoked-price":
				catalog.price.Status = "revoked"
			}
			if err := m.resumeKnownBilling(context.Background(), record); err == nil {
				t.Fatal("unverified evidence accepted")
			}
			if budgets.settleCalls != 0 {
				t.Fatal("denied evidence settled")
			}
		})
	}
}

type knownBillingAdminStore struct {
	*billingAdminFixture
	record ModelInvocation
}

func (s *knownBillingAdminStore) GetBillingRecord(_ context.Context, scope, key string) (ModelInvocation, error) {
	if scope != s.record.ScopeHash || key != s.record.Key {
		return ModelInvocation{}, ErrModelInvocationConflict
	}
	return s.record, nil
}

func TestKnownBillingAdminUsesAuthenticatedScopeAndRejectsCallerMoney(t *testing.T) {
	for _, mode := range []string{"accepted", "foreign-application", "caller-money", "unauthorized"} {
		t.Run(mode, func(t *testing.T) {
			m, record, _, _ := knownBillingFixture(t)
			m.internalToken, m.billingControl = "internal", billingControlFixture{}
			m.modelStore = &knownBillingAdminStore{billingAdminFixture: &billingAdminFixture{memoryModelInvocationStore: m.modelStore.(*memoryModelInvocationStore)}, record: record}
			body := map[string]any{"action": "reconcile_known", "scope_hash": record.ScopeHash, "idempotency_key": record.Key, "fingerprint": record.Fingerprint}
			if mode == "caller-money" {
				body["decision"] = map[string]any{"cost_micros": 1}
			}
			raw, _ := json.Marshal(body)
			r := httptest.NewRequest(http.MethodPost, "/billing/reconciliations", strings.NewReader(string(raw)))
			for k, v := range map[string]string{"X-Internal-Token": "internal", "X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "admin", "X-Tenant-ID": "tenant", "X-Department-ID": "department", "X-Application-ID": "application"} {
				r.Header.Set(k, v)
			}
			if mode == "foreign-application" {
				r.Header.Set("X-Application-ID", "foreign")
			}
			if mode == "unauthorized" {
				r.Header.Set("X-Internal-Token", "foreign")
			}
			w := httptest.NewRecorder()
			m.billingAdmin(w, r)
			want := map[string]int{"accepted": 200, "foreign-application": 409, "caller-money": 400, "unauthorized": 401}[mode]
			if w.Code != want {
				t.Fatal("wrong authority result", w.Code, want, w.Body.String())
			}
		})
	}
}

// A restarted SQL worker settles the original saved response once. The test
// catalog supplies approved metadata; neither a gateway nor a provider exists.
func TestSQLKnownResponseRecoveryPreservesOriginalUsageAndPrice(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
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
	budgets := usagecost.NewSQLStore(db)
	if err = budgets.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.SetModelBudgetClosureReader(budgets); err != nil {
		t.Fatal(err)
	}
	_, fixture, catalog, _ := knownBillingFixture(t)
	id := fmt.Sprintf("known-response-%d", time.Now().UnixNano())
	hash := sha256.Sum256([]byte(id))
	scope := hex.EncodeToString(hash[:])
	now := time.Now().UTC()
	r, _, err := store.ReserveGoverned(ctx, scope, id, fixture.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := budgets.Reserve(ctx, usagecost.ModelBudgetRequest{
		Scope: usagecost.ModelBudgetScope{TenantID: id, DepartmentID: "department", ApplicationID: "application", AgentID: "qa", AgentVersionID: "v1"},
		RunID: id, RequestID: "attempt-" + id, Fingerprint: fixture.Fingerprint, PriceVersionID: catalog.price.ID,
		Window: usagecost.ModelBudgetWindow{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}, BudgetLimitMicros: 100, ReserveMicros: 0, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = budgets.MarkReconciliationNeeded(ctx, reservation); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveBillingRecovery(ctx, scope, id, fixture.Fingerprint, fixture.Response, 0, BillingRecovery{Reservation: reservation, PriceID: catalog.price.ID, AttemptToken: r.AttemptToken}); err != nil {
		t.Fatal(err)
	}
	record, err := store.GetBillingRecord(ctx, scope, id)
	if err != nil {
		t.Fatal(err)
	}
	m := &Module{modelStore: store, modelPrices: catalog, modelBudgets: budgets}
	if err = m.resumeKnownBilling(ctx, record); err != nil {
		t.Fatal(err)
	}
	// Reopen the store as a new worker would after a process restart.
	restarted, err := NewSQLModelInvocationStore(db)
	if err != nil {
		t.Fatal(err)
	}
	m.modelStore = restarted
	m.reconcileBilling(ctx)
	m.reconcileBilling(ctx)
	got, err := restarted.GetBillingRecord(ctx, scope, id)
	if err != nil || got.Status != "completed" {
		t.Fatal("saved response not completed", err, got.Status)
	}
	var events, input, output, cost int64
	err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*),COALESCE(sum(input_tokens),0),COALESCE(sum(output_tokens),0),COALESCE(sum(cost_micros),0) FROM platform_usage_event WHERE tenant_id=? AND run_id=?`), id, id).Scan(&events, &input, &output, &cost)
	if err != nil || events != 1 || input != 239 || output != 23 || cost != 0 {
		t.Fatal("original usage changed or duplicated", err, events, input, output, cost)
	}
	var status, price string
	err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT status,price_version_id FROM platform_model_budget_reservation WHERE reservation_id=?`), reservation.ReservationID).Scan(&status, &price)
	if err != nil || status != "settled" || price != catalog.price.ID {
		t.Fatal("original price/reservation changed", err, status, price)
	}
	if err = m.resumeKnownBilling(ctx, record); err == nil {
		t.Fatal("stale recovery overwrote completed record")
	}
}
