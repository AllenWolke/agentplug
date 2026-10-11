package identity

import (
	"encoding/json"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestSQLPermissionPrincipalDirectoryScopesAndValidity(t *testing.T) {
	f := newAdministratorFixture(t)
	scope := f.command(2, "directory").Scope
	appointment := f.authenticate(t, 0, f.command(2, "directory-admin"))
	if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], appointment); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id, dept, app, status string
		starts, expires       any
	}{
		{"directory-other-app", scope.DepartmentID, "other-app", "active", nil, nil},
		{"directory-other-dept", "other-dept", "other-app", "active", nil, nil},
		{"directory-expired", scope.DepartmentID, scope.ApplicationID, "active", nil, f.now},
		{"directory-future", scope.DepartmentID, scope.ApplicationID, "active", f.now.Add(time.Hour), nil},
		{"directory-revoked", scope.DepartmentID, scope.ApplicationID, "revoked", nil, nil},
	} {
		if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: c.id, TenantID: scope.TenantID, IsActive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload,scope_hash) VALUES(?,?,?,?,?,?,1,?,?,?,?)`), c.id+"-member", c.id, scope.TenantID, c.dept, c.app, c.status, c.starts, c.expires, "{}", permissionHash([]byte(c.id))); err != nil {
			t.Fatal(err)
		}
	}
	// An inconsistent foreign-company membership must never admit a local user.
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalUser, ID: "directory-foreign-membership", TenantID: scope.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), "directory-foreign-member", "directory-foreign-membership", "foreign-tenant", scope.DepartmentID, scope.ApplicationID, "{}", permissionHash([]byte("directory-foreign-member"))); err != nil {
		t.Fatal(err)
	}
	// A second active membership in the same department must not duplicate users.
	id := f.actors[1].PrincipalID
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), "directory-duplicate", id, scope.TenantID, scope.DepartmentID, "other-app", "{}", permissionHash([]byte("directory-duplicate"))); err != nil {
		t.Fatal(err)
	}
	page, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], scope, "", 1, 2)
	if err != nil || page.Total != 3 || len(page.Items) != 2 {
		t.Fatalf("application boundary: %+v %v", page, err)
	}
	next, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], scope, "", 2, 2)
	if err != nil || next.Total != 3 || len(next.Items) != 1 || page.Items[1].ID >= next.Items[0].ID {
		t.Fatalf("page/order mismatch: %+v %v", next, err)
	}
	for _, id := range []string{"directory-other-app", "directory-other-dept", "directory-expired", "directory-future", "directory-revoked", "directory-foreign-membership", "' OR 1=1 --"} {
		result, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], scope, id, 1, 20)
		if err != nil || result.Total != 0 || len(result.Items) != 0 {
			t.Fatalf("id filter leaks %q: %+v %v", id, result, err)
		}
	}
	department := scope
	department.Type = "department"
	department.ApplicationID = ""
	if _, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], department, "", 1, 20); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("application administrator expanded directory", err)
	}
	result, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[0], department, "", 1, 20)
	if err != nil || result.Total != 4 || len(result.Items) != 4 {
		t.Fatalf("department membership validity/dedup: %+v %v", result, err)
	}
	tenant := department
	tenant.Type = "tenant"
	tenant.DepartmentID = ""
	result, err = f.store.PagePermissionPrincipals(f.ctx, f.actors[0], tenant, "", 1, 20)
	if err != nil || result.Total != 9 {
		t.Fatalf("tenant metadata: %+v %v", result, err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if len(item.Roles) != 0 || len(item.Groups) != 0 {
			t.Fatal("directory returned role/group data")
		}
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',payload=jsonb_set(payload::jsonb,'{status}','"revoked"'::jsonb)::json WHERE subject_id=? AND role_code='permission_admin'`), f.actors[2].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PagePermissionPrincipals(f.ctx, f.actors[2], scope, "", 1, 20); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("revoked directory authority survived", err)
	}
}
