package modelgovernance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func seedApprovedPriceModel(store *memoryStore, trustZone, versionStatus string) {
	store.providers["provider-price"] = Provider{ID: "provider-price", ProviderKey: "price-provider", Type: ProviderExternalManaged, TrustZone: trustZone, Status: StatusApproved, Revision: 2}
	store.definitions["definition-price"] = ModelDefinition{ID: "definition-price", ProviderID: "provider-price", ModelKey: "model-price", Kind: ModelKindChat}
	store.versions["version-price"] = ModelVersion{ID: "version-price", DefinitionID: "definition-price", SemanticVersion: "1.0.0", Status: versionStatus, Revision: 2}
}

func TestPriceCatalogCreateApproveResolveAndAdminAuthorization(t *testing.T) {
	store := newMemoryStore()
	seedApprovedPriceModel(store, TrustExternal, StatusApproved)
	var actions []Action
	module := moduleForTest(store, func(_ context.Context, actor Actor, action Action, scope Scope) error {
		if actor.PrincipalID != "admin-a" || !actor.Browser || !scope.IsGlobal() {
			return ErrForbidden
		}
		actions = append(actions, action)
		return nil
	})
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"model_version_id":"version-price","currency":"usd","input_micros_per_1k_tokens":1200,"output_micros_per_1k_tokens":2400,"effective_from":"` + start.Format(time.RFC3339) + `"}`
	response := browserRequest(module.Handler(), http.MethodPost, "/prices", body, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var draft PriceVersion
	if err := json.Unmarshal(response.Body.Bytes(), &draft); err != nil {
		t.Fatal(err)
	}
	if draft.Status != priceStatusDraft || draft.Revision != 1 || draft.CreatedBy != "admin-a" || !strings.HasPrefix(draft.ContentHash, "sha256:") {
		t.Fatalf("draft is missing immutable metadata: %+v", draft)
	}
	if strings.Contains(response.Body.String(), "secret_ref") || strings.Contains(response.Body.String(), "api_key") {
		t.Fatal("price DTO leaked provider credential material")
	}
	response = browserRequest(module.Handler(), http.MethodGet, "/prices?model_version_id=version-price&limit=1", "", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), draft.ID) {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodGet, "/prices/"+draft.ID, "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/prices/"+draft.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"approved"`) || !strings.Contains(response.Body.String(), `"revision":2`) {
		t.Fatalf("approve status=%d body=%s", response.Code, response.Body.String())
	}
	resolved, err := store.ResolvePrice(context.Background(), "version-price", start.Add(time.Hour))
	if err != nil || resolved.ID != draft.ID {
		t.Fatalf("resolver returned row=%+v err=%v", resolved, err)
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/prices/"+draft.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale approval status=%d body=%s", response.Code, response.Body.String())
	}
	if len(actions) != 5 || actions[0] != ActionCreate || actions[1] != ActionRead || actions[2] != ActionRead || actions[3] != ActionApprove || actions[4] != ActionApprove {
		t.Fatalf("unexpected authorization actions: %v", actions)
	}
	internal := httptestRequest(module, http.MethodGet, "/prices")
	if internal.Code != http.StatusForbidden {
		t.Fatalf("non-browser internal-token call must not manage catalog status=%d body=%s", internal.Code, internal.Body.String())
	}
}

func TestPriceCatalogRejectsUnknownUnapprovedAndZeroExternalRates(t *testing.T) {
	store := newMemoryStore()
	seedApprovedPriceModel(store, TrustExternal, StatusApproved)
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{name: "unknown model version", body: `{"model_version_id":"missing","currency":"USD","input_micros_per_1k_tokens":1,"output_micros_per_1k_tokens":1,"effective_from":"` + start + `"}`, want: http.StatusNotFound},
		{name: "external zero input", body: `{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":0,"output_micros_per_1k_tokens":1,"effective_from":"` + start + `"}`, want: http.StatusBadRequest},
		{name: "external zero output", body: `{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":1,"output_micros_per_1k_tokens":0,"effective_from":"` + start + `"}`, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := browserRequest(module.Handler(), http.MethodPost, "/prices", test.body, nil)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
	store.versions["version-price"] = ModelVersion{ID: "version-price", DefinitionID: "definition-price", Status: StatusDraft, Revision: 1}
	response := browserRequest(module.Handler(), http.MethodPost, "/prices", `{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":1,"output_micros_per_1k_tokens":1,"effective_from":"`+start+`"}`, nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "MODEL_VERSION_NOT_APPROVED") {
		t.Fatalf("unapproved model price status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPriceCatalogRequiresPlatformAdministratorAuthorization(t *testing.T) {
	store := newMemoryStore()
	denied := moduleForTest(store, func(_ context.Context, actor Actor, action Action, scope Scope) error {
		if actor.PrincipalID != "admin-a" || !actor.Browser || !scope.IsGlobal() || action != ActionRead {
			return ErrForbidden
		}
		return ErrForbidden
	})
	response := browserRequest(denied.Handler(), http.MethodGet, "/prices", "", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-platform administrator status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(denied.Handler(), http.MethodPost, "/prices", `{"model_version_id":"version-price","tenant_id":"tenant-a"}`, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("authorization must be checked before request body details status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPriceCatalogRejectsOverlappingIntervalsAndAllowsAdjacentIntervals(t *testing.T) {
	store := newMemoryStore()
	seedApprovedPriceModel(store, TrustLocal, StatusApproved)
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	create := func(from time.Time, until *time.Time) *PriceVersion {
		t.Helper()
		row := PriceVersion{ID: "price-" + from.Format("20060102T150405"), ModelVersionID: "version-price", Currency: "USD", InputMicrosPer1K: 0, OutputMicrosPer1K: 0, EffectiveFrom: from, EffectiveUntil: until, Status: priceStatusDraft, Revision: 1, CreatedBy: "admin-a"}
		if err := assignPriceContentHash(&row); err != nil {
			t.Fatal(err)
		}
		if err := store.CreatePriceVersion(context.Background(), &row); err != nil {
			t.Fatal(err)
		}
		return &row
	}
	end := start.Add(24 * time.Hour)
	first := create(start, &end)
	if err := store.ApprovePriceVersion(context.Background(), first.ID, 1); err != nil {
		t.Fatal(err)
	}
	response := browserRequest(module.Handler(), http.MethodPost, "/prices", `{"model_version_id":"version-price","currency":"USD","input_micros_per_1k_tokens":2,"output_micros_per_1k_tokens":3,"effective_from":"2030-01-01T12:00:00Z"}`, nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "PRICE_INTERVAL_OVERLAP") {
		t.Fatalf("overlap status=%d body=%s", response.Code, response.Body.String())
	}
	second := create(end, nil)
	if err := store.ApprovePriceVersion(context.Background(), second.ID, 1); err != nil {
		t.Fatalf("adjacent interval rejected: %v", err)
	}
	for _, at := range []time.Time{start, end, end.Add(time.Hour)} {
		if _, err := store.ResolvePrice(context.Background(), "version-price", at); err != nil {
			t.Fatalf("resolve at %s: %v", at, err)
		}
	}
}

func httptestRequest(module *Module, method, path string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer internal-token")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, request)
	return response
}

func TestExternalEmbeddingInputOnlyPricing(t *testing.T) {
	store := newMemoryStore()
	seedApprovedPriceModel(store, TrustExternal, StatusApproved)
	definition := store.definitions["definition-price"]
	definition.Kind = ModelKindEmbedding
	store.definitions[definition.ID] = definition
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	response := browserRequest(module.Handler(), http.MethodPost, "/prices", `{"model_version_id":"version-price","currency":"CNY","input_micros_per_1k_tokens":500,"output_micros_per_1k_tokens":0,"effective_from":"2030-01-01T00:00:00Z"}`, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("input-only embedding pricing rejected: %d %s", response.Code, response.Body.String())
	}
	var row PriceVersion
	if err := json.Unmarshal(response.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/prices/"+row.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", response.Code, response.Body.String())
	}
	price, err := store.ResolvePrice(context.Background(), "version-price", time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || price.InputMicrosPer1K != 500 || price.OutputMicrosPer1K != 0 {
		t.Fatalf("incorrect embedding price: %+v %v", price, err)
	}
	if err := validatePriceRates(TrustExternal, ModelKindEmbedding, 0, 0); err == nil {
		t.Fatal("unknown input cost accepted")
	}
	if err := validatePriceRates(TrustExternal, ModelKindChat, 500, 0); err == nil {
		t.Fatal("missing external chat output pricing accepted")
	}
}
