package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV2DepartmentCreationUsesCompanyAdministration(t *testing.T) {
	for _, tc := range []struct {
		role, company string
		status        int
	}{{"super_admin", "t", http.StatusCreated}, {"super_admin", "foreign", http.StatusForbidden}, {"permission_admin", "t", http.StatusForbidden}, {"operator", "t", http.StatusForbidden}} {
		t.Run(tc.role+"/"+tc.company, func(t *testing.T) {
			snapshot, _ := permissionFixture()
			snapshot.Principal.Roles = nil
			scope := ManagementScope{Type: "application", TenantID: "t", DepartmentID: "d", ApplicationID: "a"}
			if tc.role == "super_admin" {
				scope = ManagementScope{Type: "global"}
			}
			snapshot.Bindings = []RoleBinding{{ID: "binding", SubjectID: snapshot.Principal.ID, RoleCode: tc.role, RoleVersion: 1, Scope: scope, Status: "active", Revision: 1}}
			snapshot.Roles = BuiltinRoleDefinitions()
			memory := &memoryStore{principal: snapshot.Principal, tenant: Tenant{ID: "t", Status: "active"}}
			store := &permissionHTTPStore{snapshot: snapshot, memoryStore: memory}
			body, _ := json.Marshal(Department{ID: "new-department", TenantID: tc.company, Code: "new", Name: "New department", Status: "active", Revision: 1})
			r := httptest.NewRequest(http.MethodPost, "/departments", strings.NewReader(string(body)))
			setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
			r.Header.Set("Authorization", "Bearer private-token")
			r.Header.Set("X-Internal-Token", "private-token")
			w := httptest.NewRecorder()
			NewModule(store, "private-token").Handler().ServeHTTP(w, r)
			if w.Code != tc.status || (w.Code != http.StatusCreated && memory.department.ID != "") {
				t.Fatalf("status=%d expected=%d department=%q", w.Code, tc.status, memory.department.ID)
			}
		})
	}
}

func TestV2OrganizationDirectoryUsesCurrentPermissionScope(t *testing.T) {
	for _, tc := range []struct {
		name, role, bindingScope, path string
		status, count                  int
	}{
		{"super administrator sees both applications", "super_admin", "global", "/applications", 200, 2},
		{"super administrator can select application without department", "super_admin", "global", "/applications?application_id=other", 200, 1},
		{"tenant administrator sees both applications", "tenant_admin", "tenant", "/applications", 200, 2},
		{"operator sees own application", "operator", "application", "/applications", 200, 1},
		{"operator cannot select other application", "operator", "application", "/applications?application_id=other", 403, 0},
		{"operator cannot select other department", "operator", "application", "/departments?department_id=other-department", 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, _ := permissionFixture()
			snapshot.Principal.Roles = []string{"system_admin"} // Must never restore a legacy alias in v2.
			scope := ManagementScope{Type: tc.bindingScope}
			if tc.bindingScope != "global" {
				scope.TenantID = "t"
			}
			if tc.bindingScope == "application" {
				scope.DepartmentID, scope.ApplicationID = "d", "a"
			}
			snapshot.Bindings = []RoleBinding{{ID: "binding", SubjectID: snapshot.Principal.ID, RoleCode: tc.role, RoleVersion: 1, Scope: scope, Status: "active", Revision: 1}}
			if tc.bindingScope == "tenant" {
				snapshot.Memberships = append(snapshot.Memberships, Membership{ID: "tenant-member", SubjectID: snapshot.Principal.ID, Scope: scope, Status: "active", Revision: 1})
			}
			snapshot.Roles = BuiltinRoleDefinitions()
			store := &permissionHTTPStore{snapshot: snapshot, memoryStore: &memoryStore{
				principal: snapshot.Principal,
				applications: []Application{
					{ID: "a", TenantID: "t", DepartmentID: "d", Status: "active"},
					{ID: "other", TenantID: "t", DepartmentID: "other-department", Status: "active"},
				},
			}}
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			setBrowserIdentityHeaders(r, snapshot.Principal, "d", "a")
			r.Header.Set("Authorization", "Bearer private-token")
			r.Header.Set("X-Internal-Token", "private-token")
			w := httptest.NewRecorder()
			NewModule(store, "private-token").Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d expected=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			if tc.status == http.StatusOK {
				var page OrganizationPage[Application]
				if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
					t.Fatal(err)
				}
				if len(page.Items) != tc.count {
					t.Fatalf("application count=%d expected=%d", len(page.Items), tc.count)
				}
			}
		})
	}
}
