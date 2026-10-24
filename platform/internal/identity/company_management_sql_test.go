package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLCompanyManagementKeepsBusinessScopeAndChecksForeignTargets(t *testing.T) {
	f := newAdministratorFixture(t)
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	handler := NewModule(f.store, "private-fixture-token").Handler()
	call := func(actor int, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		p, err := f.store.GetPrincipal(f.ctx, PrincipalUser, f.actors[actor].PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		setBrowserIdentityHeaders(r, p, f.actors[actor].DepartmentID, f.actors[actor].ApplicationID)
		r.Header.Set("Authorization", "Bearer private-fixture-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	company, dept, app := "company-beta", "department-beta", "entry-beta"
	for _, step := range []struct {
		path string
		body any
	}{
		{"/tenants", Tenant{ID: company, Code: company, Name: "Beta company", Status: "active", Revision: 1}},
		{"/departments", Department{ID: dept, TenantID: company, Code: dept, Name: "Beta department", Status: "active", Revision: 1}},
		{"/applications", Application{ID: app, TenantID: company, DepartmentID: dept, Code: app, Name: "Beta entry", Status: "active", Revision: 1}},
	} {
		w := call(0, http.MethodPost, step.path, step.body)
		if w.Code != 201 {
			t.Fatal(step.path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/tenants?view=management-targets", "/departments?tenant_id=" + company, "/applications?tenant_id=" + company, "/principals?tenant_id=" + company, "/member-candidates?tenant_id=" + company + "&department_id=" + dept} {
		w := call(0, http.MethodGet, path, nil)
		if w.Code != 200 {
			t.Fatal("root foreign management", path, w.Code, w.Body.String())
		}
		denied := call(2, http.MethodGet, path, nil)
		if denied.Code != 403 {
			t.Fatal("ordinary user foreign management", path, denied.Code, denied.Body.String())
		}
	}
	w := call(0, http.MethodGet, "/tenants?view=management-targets&page_size=1&page=2", nil)
	var companies OrganizationPage[Tenant]
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &companies) != nil || companies.Total != 2 || len(companies.Items) != 1 {
		t.Fatal("company pagination", w.Code, w.Body.String())
	}
	w = call(0, http.MethodGet, "/tenants", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &companies) != nil || companies.Total != 1 || companies.Items[0].ID != f.actors[0].TenantID {
		t.Fatal("default directory escaped personal company", w.Code, w.Body.String())
	}
	command := PrincipalCreationCommand{Username: "beta.business", DisplayName: "Beta user", Scope: ManagementScope{Type: "application", TenantID: company, DepartmentID: dept, ApplicationID: app}, JoinDepartment: true, Reason: "create in selected company", IdempotencyKey: "create-beta-user"}
	if _, err := f.store.PreviewPrincipalCreation(f.ctx, f.actors[2], command); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary user created foreign account", err)
	}
	plan, err := f.store.PreviewPrincipalCreation(f.ctx, f.actors[0], command)
	if err != nil {
		t.Fatal("root foreign principal preview", err)
	}
	command.Password = "fixture-beta-password" // secret-scan: allow (isolated test credential)
	command.PlanDigest = plan.Digest
	command.PlanExpiresAt = plan.ExpiresAt
	receipt, err := f.store.CreatePermissionPrincipal(f.ctx, f.actors[0], command)
	if err != nil || receipt.SubjectID != command.Username {
		t.Fatal("root foreign account creation", receipt, err)
	}
	profile, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, command.Username)
	if err != nil || profile.Principal.TenantID != company || len(profile.Memberships) != 2 || len(profile.Grants) != 0 {
		t.Fatal("wrong company or unexpected business grants", profile, err)
	}
	w = call(0, http.MethodGet, "/member-candidates?tenant_id="+company+"&department_id="+dept+"&view=department-members", nil)
	var people OrganizationPage[Principal]
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &people) != nil || people.Total != 1 || people.Items[0].ID != command.Username {
		t.Fatal("foreign department member directory", w.Code, w.Body.String())
	}
	w = call(0, http.MethodGet, "/principals/"+url.PathEscape(command.Username)+"/membership-profile?tenant_id="+company+"&department_id="+dept, nil)
	if w.Code != 200 {
		t.Fatal("foreign minimal member profile", w.Code, w.Body.String())
	}
	rootSnapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, f.actors[0].PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rootSnapshot.Memberships) != 1 || rootSnapshot.Memberships[0].Scope.TenantID != f.actors[0].TenantID {
		t.Fatal("root acquired foreign business membership", rootSnapshot.Memberships)
	}
	decision, err := EvaluatePermission(rootSnapshot, PermissionQuery{Action: "run", Scope: command.Scope, ResourceID: "foreign-agent", Now: f.now})
	if err != nil || decision.Allowed || decision.Reason != "TENANT_MISMATCH" {
		t.Fatal("management became foreign business access", decision, err)
	}
	// Company-scoped organization authority cannot create another company or
	// enumerate all companies, even when it can create its own departments.
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	member := Membership{ID: "tenant-admin-membership", SubjectID: f.actors[2].PrincipalID, Scope: ManagementScope{Type: "tenant", TenantID: f.actors[2].TenantID}, Status: "active", Revision: 1}
	if err := persistMembershipMutation(f.ctx, tx, member, 0); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "tenant-admin-binding", SubjectID: f.actors[2].PrincipalID, RoleCode: "tenant_admin", RoleVersion: 1, Scope: member.Scope, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tenants?view=management-targets", "/departments?tenant_id=" + company, "/applications?tenant_id=" + company} {
		w := call(2, http.MethodGet, path, nil)
		if w.Code != 403 {
			t.Fatal("company admin escaped scope", path, w.Code, w.Body.String())
		}
	}
	w = call(2, http.MethodPost, "/tenants", Tenant{ID: "unapproved-company", Code: "unapproved-company", Name: "Denied", Status: "active", Revision: 1})
	if w.Code != 403 {
		t.Fatal("company admin created another company", w.Code, w.Body.String())
	}
}
