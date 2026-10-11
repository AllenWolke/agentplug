package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type machineProfileStore struct {
	permissionHTTPStore
	machine PermissionSnapshot
}

func (s *machineProfileStore) PermissionSnapshot(ctx context.Context, kind PrincipalType, id string) (PermissionSnapshot, error) {
	if kind == PrincipalServicePrincipal && id == s.machine.Principal.ID {
		return s.machine, nil
	}
	return s.permissionHTTPStore.PermissionSnapshot(ctx, kind, id)
}

func TestMachineAccessProfileKeepsTypeAndScopeBoundaries(t *testing.T) {
	actor, _ := permissionFixture()
	actor.Bindings[0].RoleCode = "auditor"
	machine := actor
	machine.Principal.Type = PrincipalServicePrincipal
	machine.Bindings, machine.Memberships = nil, nil
	machine.Grants = append([]Grant(nil), actor.Grants...)
	machine.Grants[0].SubjectType = PrincipalServicePrincipal
	outside := machine.Grants[0]
	outside.ID, outside.ApplicationID = "outside", "other-application"
	machine.Grants = append(machine.Grants, outside)
	store := &machineProfileStore{permissionHTTPStore: permissionHTTPStore{memoryStore: &memoryStore{principal: actor.Principal}, snapshot: actor}, machine: machine}
	handler := NewModule(store, "private-token").Handler()
	call := func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/principals/u/access-profile"+query, nil)
		setBrowserIdentityHeaders(r, actor.Principal, "d", "a")
		r.Header.Del("Authorization")
		r.Header.Set("X-Internal-Token", "private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := call("?principal_type=service_principal")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"type":"service_principal"`) || strings.Contains(w.Body.String(), "other-application") {
		t.Fatal("machine type or application filtering failed", w.Code, w.Body.String())
	}
	for _, query := range []string{"?principal_type=unknown", "?principal_type=", "?principal_type=user&principal_type=service_principal"} {
		if w := call(query); w.Code != http.StatusBadRequest {
			t.Fatal("ambiguous principal type accepted", query, w.Code)
		}
	}
	store.snapshot.Bindings[0].RoleCode = "operator"
	if w := call("?principal_type=service_principal"); w.Code != http.StatusForbidden {
		t.Fatal("same ID machine used human self-access exemption", w.Code)
	}
	store.snapshot.Bindings[0].RoleCode = "auditor"
	expired := time.Now().UTC().Add(-time.Second)
	store.snapshot.Bindings[0].ExpiresAt = &expired
	if w := call("?principal_type=service_principal"); w.Code != http.StatusForbidden {
		t.Fatal("expired administrative read authorization accepted", w.Code)
	}
	store.snapshot.Bindings[0].ExpiresAt = nil
	store.machine.Grants, store.machine.Bindings, store.machine.Memberships = nil, nil, nil
	if w := call("?principal_type=service_principal"); w.Code != http.StatusNotFound {
		t.Fatal("application reader discovered an unbound machine", w.Code)
	}
	store.snapshot.Bindings[0].Scope = ManagementScope{Type: "tenant", TenantID: actor.Principal.TenantID}
	store.snapshot.Memberships[0].Scope = store.snapshot.Bindings[0].Scope
	if w := call("?principal_type=service_principal"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"resource_grants":[]`) {
		t.Fatal("tenant reader cannot inspect empty machine profile", w.Code, w.Body.String())
	}
	store.machine.Principal.TenantID = "foreign-tenant"
	if w := call("?principal_type=service_principal"); w.Code != http.StatusNotFound {
		t.Fatal("tenant reader discovered another tenant's empty machine", w.Code)
	}
}
