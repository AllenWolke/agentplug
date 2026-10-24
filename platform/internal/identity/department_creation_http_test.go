package identity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDepartmentCreationRequiresCompanyOrganizationAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, role, scope string
		version           uint64
		status            int
	}{
		{"system administrator", "super_admin", "global", 1, http.StatusCreated},
		{"company administrator", "tenant_admin", "tenant", 1, http.StatusCreated},
		{"old department administrator", "department_admin", "department", 1, http.StatusForbidden},
		{"new department administrator", "department_admin", "department", 2, http.StatusForbidden},
		{"ordinary user", "operator", "application", 1, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, _ := permissionFixture()
			snapshot.Principal.Roles = []string{"system_admin"} // Legacy claims cannot elevate v2 roles.
			scope := ManagementScope{Type: tc.scope}
			if tc.scope != "global" {
				scope.TenantID = "t"
			}
			if tc.scope == "department" || tc.scope == "application" {
				scope.DepartmentID = "d"
			}
			if tc.scope == "application" {
				scope.ApplicationID = "a"
			}
			snapshot.Bindings = []RoleBinding{{ID: "b", SubjectID: snapshot.Principal.ID, RoleCode: tc.role, RoleVersion: tc.version, Scope: scope, Status: "active", Revision: 1}}
			snapshot.Roles = BuiltinRoleDefinitions()
			if tc.scope != "global" {
				snapshot.Memberships = []Membership{{ID: "m", SubjectID: snapshot.Principal.ID, Scope: scope, Status: "active", Revision: 1}}
			}
			memory := &memoryStore{principal: snapshot.Principal, tenant: Tenant{ID: "t", Code: "company", Name: "Company", Status: "active", Revision: 1}}
			store := &permissionHTTPStore{snapshot: snapshot, memoryStore: memory}
			r := httptest.NewRequest(http.MethodPost, "/departments", strings.NewReader(`{"id":"new-department","tenant_id":"t","code":"new-department","name":"Compliance","status":"active","revision":1}`))
			setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
			r.Header.Set("Authorization", "Bearer private-token")
			w := httptest.NewRecorder()
			NewModule(store, "private-token").Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if (memory.department.ID == "new-department") != (tc.status == http.StatusCreated) {
				t.Fatal("unexpected organization mutation")
			}
		})
	}
}
