package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestManagementCapabilityRequiresCurrentMatchingDelegation(t *testing.T) {
	snapshot, query := permissionFixture()
	snapshot.Bindings[0].RoleCode = "permission_admin"
	query.Action = "authorization.change"
	query.ResourceID, query.ResourceType = "", ""
	check := func(action string, want bool) {
		t.Helper()
		query.Action = action
		got, err := managementCapabilityAvailable(snapshot, query)
		if err != nil || got != want {
			t.Fatalf("%s: got %v err %v want %v", action, got, err, want)
		}
	}
	check("authorization.read", true)
	check("authorization.change", false)
	check("principal.disable", false)
	snapshot.Delegations = []Delegation{{SubjectID: snapshot.Principal.ID, Scope: query.Scope, Status: "active", ManagementActions: []string{"authorization.change"}}}
	check("authorization.change", true)
	check("access_request.decide", false)
	check("principal.disable", false)
	check("membership.manage", false)
	snapshot.Delegations[0].ManagementActions = []string{"membership.manage"}
	check("membership.manage", true)
	check("authorization.change", false)
	snapshot.Delegations[0].ExpiresAt = &query.Now
	check("membership.manage", false)
	snapshot.Delegations[0].ExpiresAt = nil
	snapshot.Delegations[0].Scope.ApplicationID = "other"
	check("membership.manage", false)
	snapshot.Delegations[0].Scope = query.Scope
	snapshot.Delegations[0].SubjectID = "other"
	check("membership.manage", false)
	snapshot.Delegations[0].SubjectID = snapshot.Principal.ID
	snapshot.Delegations[0].Status = "revoked"
	check("membership.manage", false)
	snapshot.Bindings[0].RoleCode = "super_admin"
	snapshot.Bindings[0].Scope = ManagementScope{Type: "global"}
	check("authorization.change", true)
	check("principal.disable", true)
	check("membership.manage", true)
	snapshot.Principal.IsActive = false
	check("authorization.change", false)
}

func TestPermissionMeSeparatesGlobalCatalogFromCompanyAndApplication(t *testing.T) {
	snapshot, _ := permissionFixture()
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	read := func() ([]string, []string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
		setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
		r.Header.Set("Authorization", "Bearer private-token")
		r.Header.Set("X-Internal-Token", "private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var body struct {
			Capabilities       []string `json:"capabilities"`
			GlobalCapabilities []string `json:"global_capabilities"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("permission projection failed: %d", w.Code)
		}
		return body.Capabilities, body.GlobalCapabilities
	}
	for _, role := range []struct {
		code    string
		version uint64
		scope   ManagementScope
	}{
		{"tenant_admin", 2, ManagementScope{Type: "tenant", TenantID: "t"}},
		{"application_admin", 1, ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}},
	} {
		store.snapshot.Bindings[0].RoleCode = role.code
		store.snapshot.Bindings[0].RoleVersion = role.version
		store.snapshot.Bindings[0].Scope = role.scope
		current, global := read()
		if !slices.Contains(current, "catalog.manage") || slices.Contains(global, "catalog.manage") {
			t.Fatalf("scoped catalog role %s leaked into global projection: current=%v global=%v", role.code, current, global)
		}
	}
	store.snapshot.Bindings[0].RoleCode = "super_admin"
	store.snapshot.Bindings[0].RoleVersion = 1
	store.snapshot.Bindings[0].Scope = ManagementScope{Type: "global"}
	_, global := read()
	if !slices.Contains(global, "catalog.manage") {
		t.Fatal("global catalog capability missing")
	}
	expired := time.Now().UTC().Add(-time.Minute)
	store.snapshot.Bindings[0].ExpiresAt = &expired
	_, global = read()
	if slices.Contains(global, "catalog.manage") {
		t.Fatal("expired global catalog capability projected")
	}
	store.snapshot.Bindings[0].ExpiresAt = nil
	store.snapshot.Bindings[0].Status = "revoked"
	_, global = read()
	if slices.Contains(global, "catalog.manage") {
		t.Fatal("revoked global catalog capability projected")
	}
}

func TestPermissionMeProjectsOnlyCurrentDelegatedManagementActions(t *testing.T) {
	snapshot, query := permissionFixture()
	snapshot.Bindings[0].RoleCode = "permission_admin"
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	read := func() []string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
		setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
		r.Header.Set("Authorization", "Bearer private-token")
		r.Header.Set("X-Internal-Token", "private-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var body struct {
			Capabilities []string `json:"capabilities"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("permission projection failed: %d", w.Code)
		}
		return body.Capabilities
	}
	if actions := read(); !slices.Contains(actions, "authorization.read") || slices.Contains(actions, "authorization.change") || slices.Contains(actions, "principal.disable") {
		t.Fatal("undelegated permission-admin actions projected", actions)
	}
	store.snapshot.Delegations = []Delegation{{SubjectID: snapshot.Principal.ID, Scope: query.Scope, Status: "active", ManagementActions: []string{"authorization.change"}}}
	if actions := read(); !slices.Contains(actions, "authorization.change") || slices.Contains(actions, "principal.disable") || slices.Contains(actions, "access_request.decide") {
		t.Fatal("unlisted delegation actions projected", actions)
	}
	store.snapshot.Delegations[0].Status = "revoked"
	if actions := read(); slices.Contains(actions, "authorization.change") {
		t.Fatal("revoked delegation remains projected", actions)
	}
}
