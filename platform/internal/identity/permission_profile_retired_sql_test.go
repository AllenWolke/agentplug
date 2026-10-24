package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLAccessProfileRetiredApplicationDoesNotHideCurrentFacts(t *testing.T) {
	f := newAdministratorFixture(t)
	actor, target := f.actors[0], f.actors[2]
	retired := actor.ApplicationID + "-retired"
	if err := f.store.CreateApplication(f.ctx, Application{ID: retired, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, Code: retired, Name: "Historical evaluation", Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := RoleBinding{ID: target.PrincipalID + "-historical-role", SubjectID: target.PrincipalID, RoleCode: "agent_developer", RoleVersion: 1, Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: retired}, Status: "active", Revision: 1, SourceID: "historical-evaluation"}
	if err := insertRoleBinding(f.ctx, tx, binding); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_application SET status='inactive' WHERE id=?`), retired); err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		t.Helper()
		p, err := f.store.GetPrincipal(f.ctx, PrincipalUser, actor.PrincipalID)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodGet, "/principals/"+target.PrincipalID+"/access-profile?principal_type=user", nil)
		setBrowserIdentityHeaders(r, p, actor.DepartmentID, actor.ApplicationID)
		r.Header.Set("Authorization", "Bearer private-fixture-token")
		w := httptest.NewRecorder()
		NewModule(f.store, "private-fixture-token").Handler().ServeHTTP(w, r)
		return w
	}
	w := call()
	var projection PermissionSnapshot
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &projection) != nil || len(projection.Memberships) != 1 || len(projection.Bindings) != 0 {
		t.Fatal("inactive history blocked current profile or was exposed as live authority", w.Code, w.Body.String())
	}
	history, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, target.PrincipalID)
	if err != nil || len(history.Bindings) != 1 || history.Bindings[0].ID != binding.ID || history.Bindings[0].Status != "active" {
		t.Fatal("read-only projection rewrote immutable historical authorization", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_role_binding SET status='revoked',revision=revision+1,payload=jsonb_set(payload::jsonb,'{status}','"revoked"'::jsonb) WHERE id=?`), f.bindings[0]); err != nil {
		t.Fatal(err)
	}
	if w := call(); w.Code != http.StatusForbidden {
		t.Fatal("previous profile request retained revoked management authority", w.Code, w.Body.String())
	}
}
