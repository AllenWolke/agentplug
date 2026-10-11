package usagecost

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSQLUsageLegacyBrowserBoundaryAndAuthorizedBudget(t *testing.T) {
	store := openModelBudgetSQLStore(t)
	scope := Scope{TenantID: fmt.Sprintf("browser-usage-%d", time.Now().UnixNano()), DepartmentID: "d", ApplicationID: "a", AgentID: "agent", AgentVersionID: "v1", RunID: "run"}
	module := NewModule(store, "token")
	authorizer := &moduleAuthorizer{allowed: true}
	module.SetAuthorizer(authorizer)
	call := func(method, path string, input any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(input)
		r := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer token")
		for key, value := range map[string]string{"X-Browser-Module": "1", "X-Principal-Type": "user", "X-Principal-ID": "alice", "X-Tenant-ID": scope.TenantID, "X-Department-ID": scope.DepartmentID, "X-Application-ID": scope.ApplicationID, "X-Agent-ID": scope.AgentID, "X-Agent-Version-ID": scope.AgentVersionID, "X-Run-ID": scope.RunID} {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		module.Handler().ServeHTTP(w, r)
		return w
	}
	ctx := context.Background()
	event := Event{ID: scope.TenantID + "-event", Scope: scope, CostMicros: 1}
	if w := call(http.MethodPost, "/events", event); w.Code != http.StatusForbidden {
		t.Fatal("browser wrote usage", w.Code)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_event WHERE event_id=?`), event.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejected usage persisted", count, err)
	}
	budget := Budget{ScopeKey: ScopeKey(scope), LimitMicros: 20}
	foreign := budget
	foreign.ScopeKey = strings.Replace(foreign.ScopeKey, ":a:", ":other:", 1)
	if w := call(http.MethodPost, "/budgets", foreign); w.Code != http.StatusForbidden {
		t.Fatal("foreign budget accepted", w.Code)
	}
	if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_usage_budget WHERE scope_key=?`), foreign.ScopeKey).Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign budget persisted", count, err)
	}
	if w := call(http.MethodPost, "/budgets", budget); w.Code != http.StatusCreated || authorizer.action != ActionManageLedgerBudget {
		t.Fatal("authorized budget failed", w.Code)
	}
	authorizer.allowed = false
	budget.LimitMicros = 999
	if w := call(http.MethodPost, "/budgets", budget); w.Code != http.StatusForbidden {
		t.Fatal("revoked budget action allowed", w.Code)
	}
	var limit int64
	if err := store.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT limit_micros FROM platform_usage_budget WHERE scope_key=?`), budget.ScopeKey).Scan(&limit); err != nil || limit != 20 {
		t.Fatal("revoked request changed budget", limit, err)
	}
	if w := call(http.MethodGet, "/snapshots", nil); w.Code != http.StatusForbidden {
		t.Fatal("raw snapshot skipped current permission", w.Code)
	}
	// Trusted local recording remains usable and exactly once after the HTTP fix.
	if _, err := store.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, event); err != nil {
		t.Fatal(err)
	}
	authorizer.allowed = true
	w := call(http.MethodGet, "/snapshots", nil)
	var snapshot Snapshot
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil || snapshot.UsedMicros != 1 {
		t.Fatal("authorized snapshot or recorder replay regression", w.Code, snapshot)
	}
}
