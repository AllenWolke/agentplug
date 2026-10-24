package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func departmentProjectionFixture() (PermissionSnapshot, ManagementScope, time.Time) {
	snapshot, query := permissionFixture()
	department := ManagementScope{Type: "department", TenantID: "t", DepartmentID: "new-department"}
	snapshot.Memberships = append(snapshot.Memberships, Membership{ID: "new-member", SubjectID: "u", Scope: department, Status: "active", Revision: 1})
	snapshot.Bindings = append(snapshot.Bindings, RoleBinding{ID: "new-manager", SubjectID: "u", RoleCode: "department_admin", RoleVersion: 2, Scope: department, Status: "active", Revision: 1})
	return snapshot, department, query.Now
}

func TestDepartmentManagementProjectionIsIndependentAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*PermissionSnapshot, time.Time)
		want   bool
	}{
		{"other login department", func(*PermissionSnapshot, time.Time) {}, true},
		{"no new department membership", func(s *PermissionSnapshot, _ time.Time) { s.Memberships = s.Memberships[:1] }, false},
		{"revoked department membership", func(s *PermissionSnapshot, _ time.Time) { s.Memberships[1].Status = "revoked" }, false},
		{"expired department membership", func(s *PermissionSnapshot, now time.Time) { s.Memberships[1].ExpiresAt = &now }, false},
		{"future department membership", func(s *PermissionSnapshot, now time.Time) {
			later := now.Add(time.Hour)
			s.Memberships[1].StartsAt = &later
		}, false},
		{"revoked management", func(s *PermissionSnapshot, _ time.Time) { s.Bindings[1].Status = "revoked" }, false},
		{"expired management", func(s *PermissionSnapshot, now time.Time) { s.Bindings[1].ExpiresAt = &now }, false},
		{"future management", func(s *PermissionSnapshot, now time.Time) {
			later := now.Add(time.Hour)
			s.Bindings[1].StartsAt = &later
		}, false},
		{"old role unchanged", func(s *PermissionSnapshot, _ time.Time) { s.Bindings[1].RoleVersion = 1 }, false},
		{"cross company", func(s *PermissionSnapshot, _ time.Time) {
			s.Bindings[1].Scope.TenantID = "other"
			s.Memberships[1].Scope.TenantID = "other"
		}, false},
		{"another subject", func(s *PermissionSnapshot, _ time.Time) { s.Bindings[1].SubjectID = "other" }, false},
		{"disabled user", func(s *PermissionSnapshot, _ time.Time) { s.Principal.IsActive = false }, false},
		{"shadow mode", func(s *PermissionSnapshot, _ time.Time) { s.Mode = "shadow" }, false},
		{"duplicate scope", func(s *PermissionSnapshot, _ time.Time) {
			duplicate := s.Bindings[1]
			duplicate.ID = "duplicate"
			s.Bindings = append(s.Bindings, duplicate)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, department, now := departmentProjectionFixture()
			tc.change(&snapshot, now)
			got, err := departmentManagementScopes(snapshot, now)
			if err != nil || (len(got) > 0) != tc.want || len(got) > 1 || len(got) == 1 && got[0] != department {
				t.Fatalf("scopes=%+v error=%v", got, err)
			}
		})
	}
}

func TestPermissionMeProjectsManagedDepartmentWithoutCurrentApplicationAuthority(t *testing.T) {
	snapshot, department, _ := departmentProjectionFixture()
	store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
	handler := NewModule(store, "private-token").Handler()
	r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
	setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
	r.Header.Set("Authorization", "Bearer private-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body struct {
		Scope        ManagementScope   `json:"scope"`
		Capabilities []string          `json:"capabilities"`
		Managed      []ManagementScope `json:"department_management_scopes"`
		Global       []string          `json:"global_capabilities"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body.Managed) != 1 || body.Managed[0] != department {
		t.Fatalf("projection failed: %d %s", w.Code, w.Body.String())
	}
	if body.Scope.DepartmentID != "d" || body.Scope.ApplicationID != "a" || slices.Contains(body.Capabilities, "membership.manage") || slices.Contains(body.Capabilities, "department.agent_access.manage") {
		t.Fatalf("other department authority leaked into login application: %+v", body)
	}
	if len(body.Global) != 0 {
		t.Fatalf("department role acquired global capabilities: %v", body.Global)
	}
}

func TestPermissionMeSeparatesGlobalFromCurrentManagementCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		scope      ManagementScope
		global     bool
	}{
		{"company platform operations", "platform_ops_admin", ManagementScope{Type: "tenant", TenantID: "t"}, false},
		{"global platform operations", "platform_ops_admin", ManagementScope{Type: "global"}, true},
		{"system administrator", "super_admin", ManagementScope{Type: "global"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, _ := permissionFixture()
			snapshot.Bindings[0].RoleCode = tc.role
			snapshot.Bindings[0].Scope = tc.scope
			store := &permissionHTTPStore{memoryStore: &memoryStore{principal: snapshot.Principal}, snapshot: snapshot}
			r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
			setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
			r.Header.Set("Authorization", "Bearer private-token")
			w := httptest.NewRecorder()
			NewModule(store, "private-token").Handler().ServeHTTP(w, r)
			var body struct {
				Current []string `json:"capabilities"`
				Global  []string `json:"global_capabilities"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil || !slices.Contains(body.Current, "model.configure") || slices.Contains(body.Global, "model.configure") != tc.global {
				t.Fatalf("capability scopes incorrect: %d %+v", w.Code, body)
			}
		})
	}
}
