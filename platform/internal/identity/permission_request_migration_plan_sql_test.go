package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func TestSQLLegacyRequestMigrationPlanIsReadOnlyAndRejectsChangedSource(t *testing.T) {
	f := newAdministratorFixture(t)
	source := legacyRequestFixture(t, f)
	// Mixed-case identifiers exercise byte-order keyset pagination, independent
	// of the table's case-insensitive collation. Finished and foreign rows excluded.
	for _, item := range []struct{ id, status, tenant string }{{"Z-source", "pending", source.TenantID}, {"a-source", "pending", source.TenantID}, {"finished", "approved", source.TenantID}, {"foreign", "pending", "foreign"}} {
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_agent_access_request(id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,revision,created_at,updated_at) SELECT ?,?,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,?,revision,created_at,updated_at FROM platform_identity_agent_access_request WHERE id=?`), item.id, item.tenant, item.status, source.ID); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := f.store.PlanLegacyPermissionRequests(f.ctx, f.actors[0], 1)
	if err != nil || plan.Validate() != nil || len(plan.Entries) != 3 || plan.Entries[0].Source.ID != "Z-source" || plan.Entries[1].Source.ID != "a-source" || plan.Entries[2].Source.ID != source.ID {
		t.Fatal("snapshot pagination or scope failed", plan, err)
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_permission_request`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("preview wrote requests", count, err)
	}
	if _, err := f.store.PlanLegacyPermissionRequests(f.ctx, f.actors[2], 1); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("ordinary subject inventoried management records", err)
	}
	entry := plan.Entries[2]
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_agent_access_request SET reason='changed without revision' WHERE id=?`), source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ImportLegacyPermissionRequestFromPlan(f.ctx, f.actors[0], entry, "checked migration"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale preview source accepted", err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_permission_request`)).Scan(&count); err != nil || count != 0 {
		t.Fatal("stale source left request", count, err)
	}
	plan, err = f.store.PlanLegacyPermissionRequests(f.ctx, f.actors[0], 2)
	if err != nil {
		t.Fatal(err)
	}
	recorded := 0
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { recorded++; return nil })
	for _, entry := range plan.Entries {
		request, err := f.store.ImportLegacyPermissionRequestFromPlan(f.ctx, f.actors[0], entry, "checked migration")
		if err != nil || request.ID != entry.Source.ID || request.Status != "pending" {
			t.Fatal(request, err)
		}
		if _, err := f.store.ImportLegacyPermissionRequestFromPlan(f.ctx, f.actors[0], entry, "repeat migration"); err != nil {
			t.Fatal(err)
		}
	}
	if recorded != 3 {
		t.Fatal("rerun duplicated audit", recorded)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE id=? AND principal_type='user'`), f.actors[0].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AuthorizeLegacyRequestMigration(f.ctx, f.actors[0]); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("disabled migration actor accepted", err)
	}
}
