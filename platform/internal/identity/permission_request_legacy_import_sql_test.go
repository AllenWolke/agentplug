package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

func legacyRequestFixture(t *testing.T, f administratorFixture) AgentAccessRequest {
	t.Helper()
	a := f.actors[2]
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='legacy' WHERE principal_type='user' AND subject_id=?`), a.PrincipalID); err != nil {
		t.Fatal(err)
	}
	r, err := f.store.CreateAgentAccessRequest(f.ctx, AgentAccessRequest{ID: "old-request", TenantID: a.TenantID, DepartmentID: a.DepartmentID, ApplicationID: a.ApplicationID, AgentID: "fixture", AgentInstanceID: "fixture-installation", SubjectType: PrincipalUser, SubjectID: a.PrincipalID, Actions: []string{"run", "history.export"}, Reason: "preserve my original selected business request", Status: "pending", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='v2' WHERE principal_type='user' AND subject_id=?`), a.PrincipalID); err != nil {
		t.Fatal(err)
	}
	stored, err := scanAgentAccessRequest(f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at FROM platform_identity_agent_access_request WHERE id=?`), r.ID))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestSQLLegacyPermissionRequestImportPreservesSourceAndUsesNewApproval(t *testing.T) {
	f := newAdministratorFixture(t)
	source := legacyRequestFixture(t, f)
	f.store.SetPermissionResourceResolver(enrollmentFixtureResolver{})
	f.store.SetAuthorizationChangeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AuthorizationChangeReceipt) error { return nil })
	if _, err := f.store.CreateAgentAccessRequest(f.ctx, source); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("v2 subject created an orphan old-format request", err)
	}
	if _, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[2], source.ID, 1, "self import"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("self approval authority accepted", err)
	}
	if _, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 2, "stale import"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("stale source revision accepted", err)
	}
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error {
		return errors.New("audit unavailable")
	})
	if _, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "migration rehearsal"); err == nil {
		t.Fatal("import committed without audit")
	}
	var count int
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_identity_permission_request WHERE id=?`), source.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed audit left imported request", count, err)
	}
	var imports int
	f.store.SetAdministrativeRecorder(func(_ context.Context, _ *sql.Tx, _ sharedkernel.Scope, e AdministrativeEvent) error {
		if e.Action == "permission_request.migrated" {
			imports++
		}
		return nil
	})
	r, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "migrate pending source without granting")
	if err != nil || r.ID != source.ID || r.Revision != source.Revision || r.Reason != source.Reason || !r.CreatedAt.Equal(source.CreatedAt) || r.LegacySource == nil || len(r.Items) != 2 || r.Items[0].Action != "run" || r.Items[1].Action != "history.export" || r.Items[0].Outcome != "pending" {
		t.Fatal("source identity or exact requested actions lost", r, err)
	}
	prior, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "retry")
	if err != nil || prior.ID != r.ID || imports != 1 {
		t.Fatal("import not idempotent", prior, imports, err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, source.SubjectID)
	if err != nil || len(snapshot.Bindings) != 0 || len(snapshot.Grants) != 0 {
		t.Fatal("import silently added a role or Grant", snapshot, err)
	}
	owned, err := f.store.GetPermissionRequest(f.ctx, f.actors[2], r.ID)
	if err != nil || owned.LegacySource == nil {
		t.Fatal("owner cannot read imported request", owned, err)
	}
	// A still-legacy reviewer must not use the old shortcut on a v2 subject.
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='legacy' WHERE subject_id=?`), f.actors[1].PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DecideAgentAccessRequest(f.ctx, f.actors[1], source.ID, f.actors[1].PrincipalID, "approved", 1, "legacy shortcut"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatal("old approval wrote unversioned grants", err)
	}
	// Granting operator is a separate explicit action; import does not infer it.
	app := r.Scope
	if err := insertFixtureOperator(t, f, app); err != nil {
		t.Fatal(err)
	}
	c := PermissionRequestDecision{RequestID: r.ID, ExpectedRevision: 1, ExpectedSubjectRevision: 1, Decision: "approved", ApprovedItemIDs: []string{"run"}, IdempotencyKey: "approve-imported-subset", Reason: "approve run only after current validation"}
	c = previewApplicationDecision(t, f, c)
	receipt, err := f.store.DecidePermissionRequest(f.ctx, f.actors[0], c)
	if err != nil || receipt.Request.Status != "approved" || receipt.Request.LegacySource == nil || receipt.Request.Items[1].Outcome != "rejected" || len(receipt.Authorization.Change.Grants) != 1 {
		t.Fatal("import did not enter current subset approval", receipt, err)
	}
	retry, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "retry after approval")
	if err != nil || retry.Status != "approved" || retry.Revision != 2 {
		t.Fatal("import replay reset approved request", retry, err)
	}
	old, err := scanAgentAccessRequest(f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_id,agent_instance_id,subject_type,subject_id,actions_json,reason,status,reviewer_id,comment,revision,created_at,updated_at FROM platform_identity_agent_access_request WHERE id=?`), source.ID))
	if err != nil || old.Status != source.Status || old.Revision != source.Revision || old.Reason != source.Reason {
		t.Fatal("migration rewrote historical source", old, err)
	}
}

func insertFixtureOperator(t *testing.T, f administratorFixture, app ManagementScope) error {
	t.Helper()
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "operator-explicit", SubjectID: f.actors[2].PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "explicit-fixture"}); err != nil {
		return err
	}
	return tx.Commit()
}

func TestSQLLegacyPermissionRequestImportConcurrentAndDisabledSubject(t *testing.T) {
	f := newAdministratorFixture(t)
	source := legacyRequestFixture(t, f)
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), source.SubjectID); err != nil {
		t.Fatal(err)
	}
	var recorded atomic.Int32
	f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error {
		recorded.Add(1)
		return nil
	})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "preserve disabled user's pending request")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if recorded.Load() != 1 {
		t.Fatal("concurrent import duplicated audit", recorded.Load())
	}
	p, err := f.store.GetPrincipal(f.ctx, PrincipalUser, source.SubjectID)
	if err != nil || p.IsActive {
		t.Fatal("import activated disabled principal", p, err)
	}
	// Altering a source with the same ID/revision must never replace the import.
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_agent_access_request SET reason='unexpected changed source' WHERE id=?`), source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ImportLegacyPermissionRequest(f.ctx, f.actors[0], source.ID, 1, "retry"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatal("source digest conflict ignored", err)
	}
}
