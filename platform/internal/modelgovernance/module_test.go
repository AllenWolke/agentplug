package modelgovernance

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu          sync.Mutex
	providers   map[string]Provider
	definitions map[string]ModelDefinition
	versions    map[string]ModelVersion
	prices      map[string]PriceVersion
	deployments map[string]Deployment
	policies    map[string]AccessPolicy
	providerKey map[string]string
	modelKey    map[string]string
	versionKey  map[string]string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{providers: map[string]Provider{}, definitions: map[string]ModelDefinition{}, versions: map[string]ModelVersion{}, prices: map[string]PriceVersion{}, deployments: map[string]Deployment{}, policies: map[string]AccessPolicy{}, providerKey: map[string]string{}, modelKey: map[string]string{}, versionKey: map[string]string{}}
}

func (s *memoryStore) EnsureSchema(context.Context) error { return nil }
func (s *memoryStore) CreateProvider(_ context.Context, row *Provider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.providerKey[row.ProviderKey]; ok {
		return ErrAlreadyExists
	}
	s.providers[row.ID] = *row
	s.providerKey[row.ProviderKey] = row.ID
	return nil
}
func (s *memoryStore) GetProvider(_ context.Context, id string) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.providers[id]
	if !ok {
		return Provider{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListProviders(_ context.Context, _ int) ([]Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]Provider, 0, len(s.providers))
	for _, row := range s.providers {
		result = append(result, row)
	}
	return result, nil
}
func (s *memoryStore) UpdateProviderStatus(_ context.Context, id string, revision uint64, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.providers[id]
	expected := StatusDraft
	if status == StatusDisabled {
		expected = StatusApproved
	}
	if !ok || row.Revision != revision || row.Status != expected || (status != StatusApproved && status != StatusDisabled) {
		return ErrRevisionConflict
	}
	row.Status, row.Revision = status, row.Revision+1
	s.providers[id] = row
	return nil
}
func (s *memoryStore) CreateDefinition(_ context.Context, row *ModelDefinition) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := row.ProviderID + ":" + row.ModelKey
	if _, ok := s.modelKey[key]; ok {
		return ErrAlreadyExists
	}
	s.definitions[row.ID], s.modelKey[key] = *row, row.ID
	return nil
}
func (s *memoryStore) GetDefinition(_ context.Context, id string) (ModelDefinition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.definitions[id]
	if !ok {
		return ModelDefinition{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListDefinitions(_ context.Context, providerID string, _ int) ([]ModelDefinition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]ModelDefinition, 0)
	for _, row := range s.definitions {
		if providerID == "" || row.ProviderID == providerID {
			result = append(result, row)
		}
	}
	return result, nil
}
func (s *memoryStore) CreateVersion(_ context.Context, row *ModelVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := row.DefinitionID + ":" + row.SemanticVersion
	if _, ok := s.versionKey[key]; ok {
		return ErrAlreadyExists
	}
	s.versions[row.ID], s.versionKey[key] = *row, row.ID
	return nil
}
func (s *memoryStore) GetVersion(_ context.Context, definitionID, id string) (ModelVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.versions[id]
	if !ok || row.DefinitionID != definitionID {
		return ModelVersion{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListVersions(_ context.Context, definitionID string, _ int) ([]ModelVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]ModelVersion, 0)
	for _, row := range s.versions {
		if row.DefinitionID == definitionID {
			result = append(result, row)
		}
	}
	return result, nil
}
func (s *memoryStore) ApproveVersion(_ context.Context, id string, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.versions[id]
	if !ok || row.Revision != revision || row.Status != StatusDraft {
		return ErrRevisionConflict
	}
	row.Status, row.Revision = StatusApproved, row.Revision+1
	s.versions[id] = row
	return nil
}

func (s *memoryStore) CreatePriceVersion(_ context.Context, row *PriceVersion) error {
	if err := validatePriceVersion(row); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	version, ok := s.versions[row.ModelVersionID]
	if !ok {
		return ErrNotFound
	}
	definition, ok := s.definitions[version.DefinitionID]
	if !ok {
		return ErrNotFound
	}
	provider, ok := s.providers[definition.ProviderID]
	if !ok {
		return ErrNotFound
	}
	if version.Status != StatusApproved || provider.Status != StatusApproved {
		return ErrRevisionConflict
	}
	if err := validatePriceRates(provider.TrustZone, definition.Kind, row.InputMicrosPer1K, row.OutputMicrosPer1K); err != nil {
		return err
	}
	if _, exists := s.prices[row.ID]; exists {
		return ErrAlreadyExists
	}
	for _, existing := range s.prices {
		if priceIntervalsOverlap(*row, existing) {
			return ErrPriceOverlap
		}
	}
	now := time.Now().UTC()
	row.CreatedAt, row.UpdatedAt = now, now
	s.prices[row.ID] = *row
	return nil
}

func (s *memoryStore) GetPriceVersion(_ context.Context, id string) (PriceVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.prices[id]
	if !ok {
		return PriceVersion{}, ErrNotFound
	}
	return row, nil
}

func (s *memoryStore) ListPriceVersions(_ context.Context, modelVersionID string, limit int) ([]PriceVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]PriceVersion, 0)
	for _, row := range s.prices {
		if modelVersionID == "" || row.ModelVersionID == modelVersionID {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID > rows[j].ID
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	if len(rows) > clampLimit(limit) {
		rows = rows[:clampLimit(limit)]
	}
	return rows, nil
}

func (s *memoryStore) ApprovePriceVersion(_ context.Context, id string, revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.prices[id]
	if !ok {
		return ErrNotFound
	}
	version, ok := s.versions[row.ModelVersionID]
	if !ok {
		return ErrNotFound
	}
	if row.Revision != revision || row.Status != priceStatusDraft || version.Status != StatusApproved {
		return ErrRevisionConflict
	}
	for _, existing := range s.prices {
		if existing.ID != row.ID && existing.Status == StatusApproved && priceIntervalsOverlap(row, existing) {
			return ErrPriceOverlap
		}
	}
	row.Status, row.Revision = StatusApproved, row.Revision+1
	row.UpdatedAt = time.Now().UTC()
	s.prices[id] = row
	return nil
}

func (s *memoryStore) ResolvePrice(_ context.Context, modelVersionID string, at time.Time) (PriceVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var match *PriceVersion
	at = at.UTC()
	for _, row := range s.prices {
		if row.ModelVersionID != modelVersionID || row.Status != StatusApproved || row.EffectiveFrom.After(at) || (row.EffectiveUntil != nil && !row.EffectiveUntil.After(at)) {
			continue
		}
		if match != nil {
			return PriceVersion{}, ErrPriceOverlap
		}
		copy := row
		match = &copy
	}
	if match == nil {
		return PriceVersion{}, ErrNotFound
	}
	return *match, nil
}

func (s *memoryStore) CreateDeployment(_ context.Context, row *Deployment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.deployments {
		if existing.ID == row.ID {
			return ErrAlreadyExists
		}
	}
	var version ModelVersion
	var found bool
	for _, v := range s.versions {
		if v.ID == row.ModelVersionID {
			version, found = v, true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	if version.Status != StatusApproved {
		return ErrRevisionConflict
	}
	s.deployments[row.ID] = *row
	return nil
}
func (s *memoryStore) GetDeployment(_ context.Context, scope Scope, id string) (Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.deployments[id]
	if !ok || row.TenantID != scope.TenantID || row.DepartmentID != scope.DepartmentID || row.ApplicationID != scope.ApplicationID {
		return Deployment{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListDeployments(_ context.Context, scope Scope, versionID string, _ int) ([]Deployment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]Deployment, 0)
	for _, row := range s.deployments {
		if row.TenantID == scope.TenantID && row.DepartmentID == scope.DepartmentID && row.ApplicationID == scope.ApplicationID && (versionID == "" || versionID == row.ModelVersionID) {
			rows = append(rows, row)
		}
	}
	return rows, nil
}
func (s *memoryStore) UpdateDeploymentHealth(_ context.Context, scope Scope, id string, revision uint64, health, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.deployments[id]
	if !ok || row.TenantID != scope.TenantID || row.DepartmentID != scope.DepartmentID || row.ApplicationID != scope.ApplicationID || row.Revision != revision || row.Status == DeploymentDisabled {
		return ErrRevisionConflict
	}
	if !validHealthTransition(health, status) {
		return ErrInvalidRequest
	}
	row.HealthStatus, row.Status, row.ObservedRevision, row.Revision = health, status, revision, row.Revision+1
	s.deployments[id] = row
	return nil
}
func (s *memoryStore) CreateAccessPolicy(_ context.Context, row *AccessPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[row.ID]; ok {
		return ErrAlreadyExists
	}
	s.policies[row.ID] = *row
	return nil
}
func (s *memoryStore) GetAccessPolicy(_ context.Context, scope Scope, id string) (AccessPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.policies[id]
	if !ok || row.TenantID != scope.TenantID || (row.DepartmentID != "" && row.DepartmentID != scope.DepartmentID) || (row.ApplicationID != "" && row.ApplicationID != scope.ApplicationID) {
		return AccessPolicy{}, ErrNotFound
	}
	return row, nil
}
func (s *memoryStore) ListAccessPolicies(_ context.Context, scope Scope, _ int) ([]AccessPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]AccessPolicy, 0)
	for _, row := range s.policies {
		if row.TenantID == scope.TenantID && (row.DepartmentID == "" || row.DepartmentID == scope.DepartmentID) && (row.ApplicationID == "" || row.ApplicationID == scope.ApplicationID) {
			rows = append(rows, row)
		}
	}
	return rows, nil
}
func (s *memoryStore) UpdateAccessPolicyStatus(_ context.Context, scope Scope, id string, revision uint64, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.policies[id]
	expected := PolicyDraft
	if status == PolicyRevoked {
		expected = PolicyApproved
	}
	if !ok || row.TenantID != scope.TenantID || (row.DepartmentID != "" && row.DepartmentID != scope.DepartmentID) || (row.ApplicationID != "" && row.ApplicationID != scope.ApplicationID) || row.Revision != revision || row.Status != expected {
		return ErrRevisionConflict
	}
	if status != PolicyApproved && status != PolicyRevoked {
		return ErrInvalidRequest
	}
	row.Status, row.Revision = status, row.Revision+1
	s.policies[id] = row
	return nil
}
func (s *memoryStore) ListApplicableAccessPolicies(_ context.Context, scope ModelAccessScope) ([]AccessPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]AccessPolicy, 0)
	now := time.Now().UTC()
	for _, row := range s.policies {
		if accessPolicyApplies(row, scope, now) {
			rows = append(rows, row)
		}
	}
	return rows, nil
}
func (s *memoryStore) GetResolvedVersion(_ context.Context, id string) (ResolvedModel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, version := range s.versions {
		if version.ID != id {
			continue
		}
		definition := s.definitions[version.DefinitionID]
		provider := s.providers[definition.ProviderID]
		return ResolvedModel{VersionID: version.ID, DefinitionID: definition.ID, ProviderID: provider.ID, ProviderKey: provider.ProviderKey, ModelKey: definition.ModelKey, Kind: definition.Kind, TrustZone: provider.TrustZone, VersionStatus: version.Status, ProviderStatus: provider.Status}, nil
	}
	return ResolvedModel{}, ErrNotFound
}

type authorizerFunc func(context.Context, Actor, Action, Scope) error

func (f authorizerFunc) AuthorizeModelGovernance(ctx context.Context, actor Actor, action Action, scope Scope) error {
	return f(ctx, actor, action, scope)
}

func moduleForTest(store *memoryStore, authorize authorizerFunc) *Module {
	module := NewModule(store, "internal-token", authorize)
	module.SetAllowLocalEndpoints(true)
	module.SetEndpointValidator(func(_ string, allowLocal bool) error {
		if !allowLocal {
			return ErrUnsafeEndpoint
		}
		return nil
	})
	return module
}

func browserRequest(handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer internal-token")
	req.Header.Set("X-Browser-Module", "1")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Department-ID", "department-a")
	req.Header.Set("X-Application-ID", "application-a")
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", "admin-a")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestBrowserAuthorizationUsesTrustedActorAndGlobalTarget(t *testing.T) {
	store := newMemoryStore()
	var observed Actor
	var observedAction Action
	var observedScope Scope
	module := moduleForTest(store, func(_ context.Context, actor Actor, action Action, scope Scope) error {
		observed, observedAction, observedScope = actor, action, scope
		return nil
	})
	response := browserRequest(module.Handler(), http.MethodGet, "/providers", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	if observed.PrincipalID != "admin-a" || observed.TenantID != "tenant-a" || observedAction != ActionRead || !observedScope.IsGlobal() {
		t.Fatalf("authorizer got untrusted actor/action/target: actor=%+v action=%q scope=%+v", observed, observedAction, observedScope)
	}
	denied := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return ErrForbidden })
	response = browserRequest(denied.Handler(), http.MethodGet, "/providers", "", nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied request status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodGet, "/providers", "", map[string]string{"X-Principal-Type": "service_principal"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-user actor status=%d", response.Code)
	}
}

func TestProviderCreateValidatesScopeSecretAndEndpoint(t *testing.T) {
	store := newMemoryStore()
	module := moduleForTest(store, func(_ context.Context, actor Actor, action Action, target Scope) error {
		if actor.PrincipalID != "admin-a" || action != ActionCreate || !target.IsGlobal() {
			return ErrForbidden
		}
		return nil
	})
	body := `{"tenant_id":"tenant-a","department_id":"department-a","application_id":"application-a","provider_key":"local-test","display_name":"Local test","type":"on_prem","trust_zone":"local","endpoint_ref":"service://local-test","secret_ref":"file://provider.key","capabilities":{"chat":true}}`
	response := browserRequest(module.Handler(), http.MethodPost, "/providers", body, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var created Provider
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !created.Scope().IsGlobal() || created.OwnerID != "admin-a" || created.SecretRef != "file://provider.key" {
		t.Fatalf("provider should be global and contain a reference only: %+v", created)
	}
	if strings.Contains(response.Body.String(), "provider-secret-value") {
		t.Fatal("provider secret value leaked")
	}
	badRef := strings.Replace(body, `"file://provider.key"`, `"sk-live-provider-secret"`, 1)
	response = browserRequest(module.Handler(), http.MethodPost, "/providers", badRef, nil)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "INVALID_SECRET_REF") {
		t.Fatalf("raw secret ref status=%d body=%s", response.Code, response.Body.String())
	}
	badEndpoint := strings.Replace(body, `"service://local-test"`, `"https://provider.example/v1"`, 1)
	response = browserRequest(module.Handler(), http.MethodPost, "/providers", badEndpoint, nil)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "UNSAFE_ENDPOINT") {
		t.Fatalf("direct URL must not bypass symbolic endpoint registry: status=%d body=%s", response.Code, response.Body.String())
	}
	badScope := strings.Replace(body, `"tenant-a"`, `"tenant-b"`, 1)
	response = browserRequest(module.Handler(), http.MethodPost, "/providers", badScope, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("body scope mismatch status=%d body=%s", response.Code, response.Body.String())
	}
	if len(store.providers) != 1 {
		t.Fatalf("invalid requests persisted %d providers", len(store.providers)-1)
	}
}

func (p Provider) Scope() Scope {
	return Scope{TenantID: p.TenantID, DepartmentID: p.DepartmentID, ApplicationID: p.ApplicationID}
}

func TestProviderAndModelVersionStatusUseRevisionCAS(t *testing.T) {
	store := newMemoryStore()
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	providerBody := `{"provider_key":"local-test","display_name":"Local test","type":"on_prem","trust_zone":"local","endpoint_ref":"service://local-model","secret_ref":"secret://model/local","capabilities":{"chat":true}}`
	response := browserRequest(module.Handler(), http.MethodPost, "/providers", providerBody, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("provider status=%d %s", response.Code, response.Body.String())
	}
	var provider Provider
	_ = json.Unmarshal(response.Body.Bytes(), &provider)
	if provider.Status != StatusDraft || provider.Revision != 1 {
		t.Fatalf("provider initial state=%+v", provider)
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/providers/"+provider.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/providers/"+provider.ID+"/disable", `{"revision":1}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale provider revision status=%d body=%s", response.Code, response.Body.String())
	}
	definitionBody := `{"provider_id":"` + provider.ID + `","model_key":"model-a","kind":"chat","display_name":"Model A","context_limit":4096,"capabilities":{"streaming":true}}`
	response = browserRequest(module.Handler(), http.MethodPost, "/models", definitionBody, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("definition status=%d body=%s", response.Code, response.Body.String())
	}
	var definition ModelDefinition
	_ = json.Unmarshal(response.Body.Bytes(), &definition)
	versionBody := `{"semantic_version":"1.0.0","provider_fingerprint":"provider-fingerprint-v1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","quantization":"int8","capability_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
	response = browserRequest(module.Handler(), http.MethodPost, "/models/"+definition.ID+"/versions", versionBody, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("version status=%d body=%s", response.Code, response.Body.String())
	}
	var version ModelVersion
	_ = json.Unmarshal(response.Body.Bytes(), &version)
	response = browserRequest(module.Handler(), http.MethodPost, "/models/"+definition.ID+"/versions/"+version.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("version approve status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/models/"+definition.ID+"/versions/"+version.ID+"/approve", `{"revision":1}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("repeat approval status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/models/"+definition.ID+"/versions/"+version.ID+"/approve", `{"revision":2}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("unknown current state transition status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/providers/"+provider.ID+"/disable", `{"revision":2}`, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("approved provider disable status=%d body=%s", response.Code, response.Body.String())
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/providers/"+provider.ID+"/approve", `{"revision":3}`, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("disabled provider reapproval status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestModuleRejectsBadTokenAndMalformedJSON(t *testing.T) {
	store := newMemoryStore()
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	badToken := httptest.NewRequest(http.MethodGet, "/providers", nil)
	badToken.Header.Set("Authorization", "Bearer wrong")
	response := httptest.NewRecorder()
	module.Handler().ServeHTTP(response, badToken)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status=%d", response.Code)
	}
	for _, body := range []string{`{"provider_key":"x","unknown":true}`, `{"provider_key":`, `{} {}`} {
		response = browserRequest(module.Handler(), http.MethodPost, "/providers", body, nil)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("malformed body %q status=%d body=%s", body, response.Code, response.Body.String())
		}
	}
}

func TestValidateEndpointRejectsSSRFAndAllowsOnlyExplicitLoopback(t *testing.T) {
	lookup := func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.8")}, nil }
	if err := ValidateEndpointContext(context.Background(), "https://provider.example", false, lookup); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("private DNS result err=%v", err)
	}
	publicLookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}
	if err := ValidateEndpointContext(context.Background(), "https://provider.example", false, publicLookup); err != nil {
		t.Fatalf("public endpoint rejected: %v", err)
	}
	if err := ValidateEndpointContext(context.Background(), "https://provider.example:9443", false, publicLookup); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("unapproved port err=%v", err)
	}
	if err := ValidateEndpointContext(context.Background(), "http://127.0.0.1:8000", true, nil); err != nil {
		t.Fatalf("explicit loopback endpoint err=%v", err)
	}
	if err := ValidateEndpointContext(context.Background(), "http://127.0.0.1:8000", false, nil); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("unapproved loopback err=%v", err)
	}
}

func TestModelCreationRequiresApprovedProviderAndRejectsUnknownVersionStatus(t *testing.T) {
	store := newMemoryStore()
	module := moduleForTest(store, func(context.Context, Actor, Action, Scope) error { return nil })
	provider := Provider{ID: "provider-1", ProviderKey: "local", DisplayName: "Local", Type: ProviderOnPrem, TrustZone: TrustLocal, EndpointRef: "service://local", SecretRef: "secret://model/local", Status: StatusDraft, Revision: 1}
	if err := store.CreateProvider(context.Background(), &provider); err != nil {
		t.Fatal(err)
	}
	body := `{"provider_id":"provider-1","model_key":"m1","kind":"chat","display_name":"M1","context_limit":100}`
	response := browserRequest(module.Handler(), http.MethodPost, "/models", body, nil)
	if response.Code != http.StatusConflict {
		t.Fatalf("model under draft provider status=%d body=%s", response.Code, response.Body.String())
	}
	if err := store.UpdateProviderStatus(context.Background(), "provider-1", 1, "mystery"); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("unknown Provider state accepted: %v", err)
	}
	if err := store.UpdateProviderStatus(context.Background(), "provider-1", 1, StatusApproved); err != nil {
		t.Fatal(err)
	}
	response = browserRequest(module.Handler(), http.MethodPost, "/models", body, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("model after provider approval status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSQLStoreRequiresDB(t *testing.T) {
	if err := NewSQLStore(nil).EnsureSchema(context.Background()); err == nil {
		t.Fatal("nil SQL database accepted")
	}
}

func TestSymbolicEndpointReferencesCannotEncodeNetworkTargets(t *testing.T) {
	for _, endpoint := range []string{"service://model-gateway", "k8s://models/qwen", "ref://approved-model"} {
		if err := ValidateEndpointContext(context.Background(), endpoint, false, nil); err != nil {
			t.Fatalf("registered symbolic endpoint %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"service://169.254.169.254", "service://localhost:8080", "k8s://namespace/../../metadata", "ref://internal.example", "service://model-gateway@metadata"} {
		if err := ValidateEndpointContext(context.Background(), endpoint, false, nil); !errors.Is(err, ErrUnsafeEndpoint) {
			t.Fatalf("network target disguised as symbolic endpoint %q was accepted: %v", endpoint, err)
		}
	}
}
