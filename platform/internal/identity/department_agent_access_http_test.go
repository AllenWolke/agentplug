package identity

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type departmentAgentHTTPStore struct {
	*permissionHTTPStore
	calls int
	actor sharedkernel.Scope
}

func (s *departmentAgentHTTPStore) DepartmentAgentPolicy(_ context.Context, actor sharedkernel.Scope, tenant, department string) (DepartmentAgentPolicyState, error) {
	s.calls++
	s.actor = actor
	return DepartmentAgentPolicyState{Managed: true, Policy: DepartmentAgentPolicy{TenantID: tenant, DepartmentID: department}}, nil
}
func (s *departmentAgentHTTPStore) PreviewDepartmentAgentChange(_ context.Context, actor sharedkernel.Scope, _ DepartmentAgentChangeCommand) (DepartmentAgentChangePlan, error) {
	s.calls++
	s.actor = actor
	return DepartmentAgentChangePlan{}, nil
}
func (s *departmentAgentHTTPStore) CommitDepartmentAgentChange(_ context.Context, actor sharedkernel.Scope, _ DepartmentAgentChangeCommand) (DepartmentAgentChangeReceipt, error) {
	s.calls++
	s.actor = actor
	return DepartmentAgentChangeReceipt{}, ErrStepUpRequired
}
func (s *departmentAgentHTTPStore) DepartmentAgentChangeReceipt(_ context.Context, actor sharedkernel.Scope, _ string) (DepartmentAgentChangeReceipt, error) {
	s.calls++
	s.actor = actor
	return DepartmentAgentChangeReceipt{}, sql.ErrNoRows
}

func TestDepartmentAgentHTTPTrustedActorAndStrictCommands(t *testing.T) {
	snapshot, _ := permissionFixture()
	s := &departmentAgentHTTPStore{permissionHTTPStore: &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}}
	handler := NewModule(s, "fixture-internal-token").Handler()
	call := func(method, path, body string, authenticated, browser bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if browser {
			setBrowserIdentityHeaders(r, s.principal, "d", "a")
		}
		r.Header.Del("Authorization")
		r.Header.Del("X-Internal-Token")
		if authenticated {
			r.Header.Set("X-Internal-Token", "fixture-internal-token")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/department-agent-changes:preview", "/department-agent-changes"} {
		if w := call("POST", path, `{}`, false, true); w.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated administrative command", w.Code)
		}
		if w := call("POST", path, `{}`, true, false); w.Code != http.StatusForbidden {
			t.Fatal("service authentication implied human authority", w.Code)
		}
		if w := call("POST", path, `{"actor_id":"other-user"}`, true, true); w.Code != http.StatusBadRequest {
			t.Fatal("untrusted actor command field accepted", w.Code)
		}
	}
	if s.calls != 0 {
		t.Fatal("unauthenticated or unknown-field command reached repository")
	}
	if w := call("GET", "/department-agent-policy?tenant_id=t&tenant_id=other&department_id=d", "", true, true); w.Code != http.StatusBadRequest {
		t.Fatal("ambiguous target scope accepted", w.Code)
	}
	if w := call("GET", "/department-agent-policy?tenant_id=t&department_id=d", "", true, true); w.Code != http.StatusOK || s.actor.PrincipalID != snapshot.Principal.ID {
		t.Fatal("policy read lost trusted actor", w.Code)
	}
	if w := call("POST", "/department-agent-changes", `{}`, true, true); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "STEP_UP_REQUIRED") {
		t.Fatal("fresh proof error not preserved", w.Code)
	}
	if w := call("GET", "/department-agent-changes/original-key", "", true, true); w.Code != http.StatusNotFound {
		t.Fatal("missing receipt treated as a new command", w.Code)
	}
	before := s.calls
	if w := call("POST", "/department-agent-changes/original-key", `{}`, true, true); w.Code != http.StatusMethodNotAllowed || s.calls != before {
		t.Fatal("receipt endpoint executed a command", w.Code)
	}
}
