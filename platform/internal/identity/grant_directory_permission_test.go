package identity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLegacyGrantDirectoryUsesCurrentVersionedReadScope(t *testing.T) {
	snapshot, _ := permissionFixture()
	snapshot.Bindings[0].RoleCode = "auditor"
	snapshot.Principal.Roles = []string{"admin"}
	visible := snapshot.Grants[0]
	foreign := visible
	foreign.ID, foreign.TenantID, foreign.DepartmentID, foreign.ApplicationID = "foreign-grant", "other-t", "other-d", "other-a"
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal, grants: []Grant{visible, foreign}}, snapshot: snapshot}
	handler := NewModule(store, "internal").Handler()
	call := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/grants"+query, nil)
		setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
		r.Header.Del("Authorization")
		r.Header.Set("X-Internal-Token", "internal")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call(""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"id":"g"`) || strings.Contains(w.Body.String(), "foreign-grant") {
		t.Fatal("v2 reader lost compatibility or saw foreign grants", w.Code, w.Body.String())
	}
	if w := call("?tenant_id=other-t&department_id=other-d&application_id=other-a&agent_instance_id=i"); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "foreign-grant") {
		t.Fatal("v2 reader escaped authorized scope", w.Code, w.Body.String())
	}
	store.snapshot.Bindings[0].Status = "revoked"
	if w := call(""); w.Code != http.StatusForbidden {
		t.Fatal("old admin role bypassed revoked v2 binding", w.Code)
	}
	store.snapshot.Bindings[0].Status = "active"
	expired := time.Now().UTC().Add(-time.Second)
	store.snapshot.Bindings[0].ExpiresAt = &expired
	if w := call(""); w.Code != http.StatusForbidden {
		t.Fatal("expired v2 binding read grant directory", w.Code)
	}
	store.snapshot.Bindings[0].ExpiresAt = nil
	store.failure = errors.New("IAM unavailable")
	if w := call(""); w.Code != http.StatusServiceUnavailable {
		t.Fatal("IAM outage recovered old admin role", w.Code)
	}
}
