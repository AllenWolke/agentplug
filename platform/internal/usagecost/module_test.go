package usagecost

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type moduleStore struct {
	ledger *Ledger
}

func newModuleStore() *moduleStore                                        { return &moduleStore{ledger: NewLedger()} }
func (s *moduleStore) EnsureSchema(context.Context) error                 { return nil }
func (s *moduleStore) SetBudget(_ context.Context, b Budget) error        { return s.ledger.SetBudget(b) }
func (s *moduleStore) Apply(_ context.Context, e Event) (Snapshot, error) { return s.ledger.Apply(e) }
func (s *moduleStore) GetSnapshot(_ context.Context, scope Scope) (Snapshot, error) {
	return s.ledger.Snapshot(scope), nil
}
func (s *moduleStore) AggregateUsage(ctx context.Context, scope Scope, from, to time.Time) (UsageAggregate, error) {
	return s.ledger.AggregateUsage(ctx, scope, from, to)
}
func (s *moduleStore) ListUsageEvents(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageEventPage, error) {
	return s.ledger.ListUsageEvents(ctx, scope, from, to, page, pageSize)
}
func (s *moduleStore) ListRuns(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageRunPage, error) {
	return s.ledger.ListRuns(ctx, scope, from, to, page, pageSize)
}
func (s *moduleStore) ListRunSteps(ctx context.Context, scope Scope, from, to time.Time, page, pageSize int) (UsageStepPage, error) {
	return s.ledger.ListRunSteps(ctx, scope, from, to, page, pageSize)
}

type moduleAuthorizer struct {
	allowed bool
	err     error
	calls   int
	actor   Actor
	action  UsageAction
	scope   Scope
}

func (a *moduleAuthorizer) AuthorizeUsageCost(_ context.Context, actor Actor, action UsageAction, scope Scope) error {
	a.calls++
	a.actor, a.action, a.scope = actor, action, scope
	if a.err != nil {
		return a.err
	}
	if !a.allowed {
		return ErrUsageForbidden
	}
	return nil
}

func TestUsageModulePublishesIdempotentEventAndScopedSnapshot(t *testing.T) {
	store := newModuleStore()
	handler := NewModule(store, "token").Handler()
	event := `{"id":"usage-1","scope":{"tenant_id":"tenant","department_id":"department","application_id":"application","agent_id":"qa","agent_version_id":"v1","run_id":"run-1"},"provider":"local","model":"model","input_tokens":3,"output_tokens":2,"cost_micros":5}`
	call := func(method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if out := call(http.MethodPost, "/events", event, "", nil); out.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status=%d", out.Code)
	}
	if out := call(http.MethodPost, "/events", event, "token", nil); out.Code != http.StatusAccepted {
		t.Fatalf("first event status=%d body=%s", out.Code, out.Body.String())
	}
	if out := call(http.MethodPost, "/events", event, "token", nil); out.Code != http.StatusAccepted {
		t.Fatalf("replay status=%d body=%s", out.Code, out.Body.String())
	}
	if out := call(http.MethodGet, "/snapshots", "", "token", map[string]string{"X-Tenant-ID": "tenant", "X-Department-ID": "department", "X-Application-ID": "application", "X-Agent-ID": "qa", "X-Agent-Version-ID": "v1", "X-Run-ID": "run-1"}); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"used_micros":5`) {
		t.Fatalf("snapshot status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestUsageModuleRejectsConflictingEvent(t *testing.T) {
	store := newModuleStore()
	handler := NewModule(store, "token").Handler()
	base := `{"id":"usage-1","scope":{"tenant_id":"tenant","department_id":"department","application_id":"application","agent_id":"qa","agent_version_id":"v1","run_id":"run-1"},"provider":"local","model":"model","input_tokens":3,"output_tokens":2,"cost_micros":5}`
	for _, body := range []string{base, strings.Replace(base, `"cost_micros":5`, `"cost_micros":6`, 1)} {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer token")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		if body == base && out.Code != http.StatusAccepted {
			t.Fatalf("first status=%d", out.Code)
		}
		if body != base && out.Code != http.StatusConflict {
			t.Fatalf("conflict status=%d body=%s", out.Code, out.Body.String())
		}
	}
}

func TestUsageLegacyWritersRejectBrowserAndSnapshotUsesCurrentAuthority(t *testing.T) {
	store := newModuleStore()
	module := NewModule(store, "token")
	authorizer := &moduleAuthorizer{allowed: true}
	module.SetAuthorizer(authorizer)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer token")
		for key, value := range map[string]string{"X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": "tenant", "X-Department-ID": "department", "X-Application-ID": "application", "X-Agent-ID": "qa", "X-Agent-Version-ID": "v1", "X-Run-ID": "run-1"} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		module.Handler().ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/events"} {
		if out := call(http.MethodPost, path, `{}`); out.Code != http.StatusForbidden {
			t.Fatal("browser obtained ledger write access", path, out.Code)
		}
	}
	if len(store.ledger.events) != 0 || len(store.ledger.budgets) != 0 {
		t.Fatal("rejected browser request changed usage state")
	}
	budget := `{"scope_key":"tenant:department:application:qa:v1","limit_micros":20}`
	if out := call(http.MethodPost, "/budgets", strings.Replace(budget, "application:qa", "foreign:qa", 1)); out.Code != http.StatusForbidden {
		t.Fatal("foreign budget accepted", out.Code)
	}
	if len(store.ledger.budgets) != 0 {
		t.Fatal("cross-scope budget changed the ledger")
	}
	if out := call(http.MethodPost, "/budgets", budget); out.Code != http.StatusCreated || authorizer.action != ActionManageLedgerBudget {
		t.Fatal("authorized budget management unavailable", out.Code)
	}
	if len(store.ledger.budgets) != 1 {
		t.Fatal("authorized budget missing")
	}
	authorizer.allowed = false
	if out := call(http.MethodPost, "/budgets", budget); out.Code != http.StatusForbidden {
		t.Fatal("budget mutation survived revocation", out.Code)
	}
	authorizer.allowed = true
	authorizer.calls = 0
	if out := call(http.MethodGet, "/snapshots", ""); out.Code != http.StatusOK || authorizer.calls != 1 || authorizer.action != ActionReadUsage {
		t.Fatal("snapshot skipped current authority", out.Code)
	}
	authorizer.allowed = false
	if out := call(http.MethodGet, "/snapshots", ""); out.Code != http.StatusForbidden {
		t.Fatal("snapshot remained readable after revocation", out.Code)
	}
	authorizer.err = errors.New("identity unavailable")
	if out := call(http.MethodGet, "/snapshots", ""); out.Code != http.StatusServiceUnavailable {
		t.Fatal("snapshot outage returned previous allow", out.Code)
	}
	module.SetAuthorizer(nil)
	if out := call(http.MethodGet, "/snapshots", ""); out.Code != http.StatusForbidden {
		t.Fatal("snapshot without identity authority allowed", out.Code)
	}
}

func TestUsageModuleBrowserReadUsesInjectedAuthorizerAndScopedReadModels(t *testing.T) {
	store := newModuleStore()
	start := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	scope := Scope{TenantID: "tenant-a", DepartmentID: "dept-a", ApplicationID: "app-a", AgentID: "agent-a", AgentVersionID: "v1", RunID: "run-a"}
	if _, err := store.ledger.Apply(Event{ID: "event-a", Scope: scope, Provider: "p", Model: "m", InputTokens: 4, OutputTokens: 3, CostMicros: 9}); err != nil {
		t.Fatal(err)
	}
	store.ledger.createdAt["event-a"] = start.Add(time.Hour)
	other := scope
	other.TenantID = "tenant-b"
	if _, err := store.ledger.Apply(Event{ID: "event-b", Scope: other, InputTokens: 99, CostMicros: 99}); err != nil {
		t.Fatal(err)
	}
	store.ledger.createdAt["event-b"] = start.Add(time.Hour)
	authorizer := &moduleAuthorizer{allowed: true}
	module := NewModule(store, "token")
	module.SetAuthorizer(authorizer)
	handler := module.Handler()
	request := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", "user-a")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	period := "from=2026-09-24T00:00:00Z&to=2026-09-25T00:00:00Z&agent_id=agent-a&agent_version_id=v1&run_id=run-a"
	if out := request("/usage/aggregate?" + period); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"event_count":1`) || !strings.Contains(out.Body.String(), `"cost_micros":9`) {
		t.Fatalf("aggregate status=%d body=%s", out.Code, out.Body.String())
	}
	if authorizer.calls != 1 || authorizer.actor.PrincipalID != "user-a" || authorizer.action != ActionReadUsage || authorizer.scope.TenantID != "tenant-a" {
		t.Fatalf("authorizer input calls=%d actor=%+v action=%q scope=%+v", authorizer.calls, authorizer.actor, authorizer.action, authorizer.scope)
	}
	if out := request("/usage/events?" + period + "&page=1&page_size=1"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"total":1`) || !strings.Contains(out.Body.String(), `"event-a"`) {
		t.Fatalf("events status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("/usage/runs?" + period + "&page=1&page_size=1"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"event_count":1`) || !strings.Contains(out.Body.String(), `"run_id":"run-a"`) {
		t.Fatalf("runs status=%d body=%s", out.Code, out.Body.String())
	}
	if out := request("/usage/runs/run-a/steps?from=2026-09-24T00:00:00Z&to=2026-09-25T00:00:00Z&agent_id=agent-a&agent_version_id=v1&page=1&page_size=1"); out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"event_id":"event-a"`) || !strings.Contains(out.Body.String(), `"index":1`) {
		t.Fatalf("run steps status=%d body=%s", out.Code, out.Body.String())
	}
	if authorizer.scope.RunID != "run-a" {
		t.Fatalf("step authorization must include the path run ID: %+v", authorizer.scope)
	}
}

func TestUsageModuleBrowserReadFailsClosedForMissingAuthorizerOrScope(t *testing.T) {
	module := NewModule(newModuleStore(), "token")
	handler := module.Handler()
	call := func(path string, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", "user-a")
		req.Header.Set("X-Tenant-ID", tenant)
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	query := "/usage/aggregate?from=2026-09-24T00:00:00Z&to=2026-09-25T00:00:00Z"
	if out := call(query, "tenant-a"); out.Code != http.StatusForbidden {
		t.Fatalf("missing authorizer status=%d body=%s", out.Code, out.Body.String())
	}
	if out := call(query, ""); out.Code != http.StatusBadRequest {
		t.Fatalf("empty scope status=%d body=%s", out.Code, out.Body.String())
	}
}

func TestUsageModuleReadRejectsTenantOverrideAndOversizedPage(t *testing.T) {
	authorizer := &moduleAuthorizer{allowed: true}
	module := NewModule(newModuleStore(), "token")
	module.SetAuthorizer(authorizer)
	handler := module.Handler()
	call := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-Browser-Module", "1")
		req.Header.Set("X-Principal-Type", "user")
		req.Header.Set("X-Principal-ID", "user-a")
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Department-ID", "dept-a")
		req.Header.Set("X-Application-ID", "app-a")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	period := "from=2026-09-24T00:00:00Z&to=2026-09-25T00:00:00Z"
	if out := call("/usage/aggregate?" + period + "&tenant_id=tenant-b"); out.Code != http.StatusBadRequest {
		t.Fatalf("tenant override status=%d body=%s", out.Code, out.Body.String())
	}
	if out := call("/usage/events?" + period + "&page_size=101"); out.Code != http.StatusBadRequest {
		t.Fatalf("oversized page status=%d body=%s", out.Code, out.Body.String())
	}
	if out := call("/usage/executions?" + period); out.Code != http.StatusNotFound {
		t.Fatalf("event rows must not be exposed as executions: status=%d body=%s", out.Code, out.Body.String())
	}
	if authorizer.calls != 0 {
		t.Fatalf("invalid requests must not reach authorizer; calls=%d", authorizer.calls)
	}
}

func TestUsageModuleBrowserReadMapsAuthorizerFailure(t *testing.T) {
	authorizer := &moduleAuthorizer{err: errors.New("identity unavailable")}
	module := NewModule(newModuleStore(), "token")
	module.SetAuthorizer(authorizer)
	handler := module.Handler()
	req := httptest.NewRequest(http.MethodGet, "/usage/aggregate?from=2026-09-24T00:00:00Z&to=2026-09-25T00:00:00Z", nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Browser-Module", "1")
	req.Header.Set("X-Principal-Type", "user")
	req.Header.Set("X-Principal-ID", "user-a")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Department-ID", "dept-a")
	req.Header.Set("X-Application-ID", "app-a")
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("authorizer error status=%d body=%s", out.Code, out.Body.String())
	}
}
