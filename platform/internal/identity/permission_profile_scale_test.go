package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type countedProfileStore struct {
	machineProfileStore
	checks      map[ManagementScope]int
	failedScope ManagementScope
}

func (s *countedProfileStore) ResolvePermission(ctx context.Context, kind PrincipalType, id string, q PermissionQuery) (PermissionDecision, error) {
	s.checks[q.Scope]++
	if q.Scope == s.failedScope {
		return PermissionDecision{}, errors.New("fixture storage unavailable")
	}
	return s.permissionHTTPStore.ResolvePermission(ctx, kind, id, q)
}
func TestAccessProfileChecksEachCompleteScopeOnceAndRechecksNextRequest(t *testing.T) {
	actor, _ := permissionFixture()
	actor.Bindings[0].RoleCode = "auditor"
	target := actor
	target.Principal.Type = PrincipalServicePrincipal
	target.Memberships = nil
	target.Bindings = nil
	target.Grants = nil
	allowed := ManagementScope{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "a", ResourceID: "i"}
	hidden := []ManagementScope{
		{Type: "agent_installation", TenantID: "foreign", DepartmentID: "d", ApplicationID: "a", ResourceID: "i"},
		{Type: "agent_installation", TenantID: "t", DepartmentID: "other", ApplicationID: "a", ResourceID: "i"},
		{Type: "agent_installation", TenantID: "t", DepartmentID: "d", ApplicationID: "other", ResourceID: "i"},
		{Type: "tenant", TenantID: "t"},
	}
	for n := 0; n < 600; n++ {
		target.Assignments = append(target.Assignments, TaskAssignment{ID: fmt.Sprint(n), SubjectID: "u", TaskID: fmt.Sprint(n), Action: "business.review", Scope: allowed, Status: "active", Revision: 1})
	}
	for n, scope := range hidden {
		target.Assignments = append(target.Assignments, TaskAssignment{ID: fmt.Sprint("hidden-", n), SubjectID: "u", TaskID: fmt.Sprint("hidden-", n), Action: "business.review", Scope: scope, Status: "active", Revision: 1})
	}
	store := &countedProfileStore{machineProfileStore: machineProfileStore{permissionHTTPStore: permissionHTTPStore{memoryStore: &memoryStore{principal: actor.Principal}, snapshot: actor}, machine: target}, checks: map[ManagementScope]int{}}
	handler := NewModule(store, "private-token").Handler()
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/principals/u/access-profile?principal_type=service_principal", nil)
		setBrowserIdentityHeaders(r, actor.Principal, "d", "a")
		r.Header.Del("Authorization")
		r.Header.Set("X-Internal-Token", "private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := call()
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var result PermissionSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Assignments) != 600 {
		t.Fatal("scope filtering changed", len(result.Assignments))
	}
	if len(store.checks) != 6 {
		t.Fatal("complete scope keys not preserved", store.checks)
	}
	for scope, count := range store.checks {
		if count != 1 {
			t.Fatal("repeated scope check", scope, count)
		}
	}
	store.snapshot.Bindings[0].RoleCode = "operator"
	if w := call(); w.Code != http.StatusForbidden {
		t.Fatal("previous request decision survived revocation", w.Code)
	}
	app := ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
	if store.checks[app] != 2 {
		t.Fatal("fresh authorization check missing", store.checks)
	}
	store.snapshot.Bindings[0].RoleCode = "auditor"
	store.failedScope = allowed
	if w := call(); w.Code < 500 {
		t.Fatal("scope storage failure did not fail closed", w.Code)
	}
}
