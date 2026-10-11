package identity

import (
	"encoding/json"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
)

func TestSQLAuthorizationEpochScopeShrinkRevocationAndOutageNeverReturnOldVersion(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[2]
	scope := actor
	scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID = "epoch-failure-installation", "epoch-failure-installation", "fixture", "v1"
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "epoch-failure-role", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	grant := Grant{ID: "epoch-failure-grant", SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: scope.AgentInstanceID, ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: DataScope{Type: "owner"}}
	if err := insertPermissionGrant(f.ctx, tx, grant, f.now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	initial, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run")
	if err != nil || initial != 1 {
		t.Fatal(initial, err)
	}
	// Simulate the persisted result of narrowing a Grant, keeping the same role
	// and allowed operation. Old capabilities must still lose their epoch.
	grant.DataScope = DataScope{Type: "explicit_set", IDs: []string{"retained-record"}}
	grant.Revision++
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET permission_json=?,revision=?,grant_key_hash=? WHERE id=?`), string(raw), grant.Revision, grantKeyHash(grant), grant.ID); err != nil {
		t.Fatal(err)
	}
	narrowed, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run")
	if err != nil || narrowed != initial+1 {
		t.Fatal("scope shrink reused old epoch", narrowed, err)
	}
	snapshot, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	member := snapshot.Memberships[0]
	member.Status = "revoked"
	member.Revision++
	raw, err = json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_membership SET payload=?,status='revoked',revision=? WHERE id=?`), string(raw), member.Revision, member.ID); err != nil {
		t.Fatal(err)
	}
	if epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err == nil || epoch != 0 {
		t.Fatal("revoked member received cached epoch", epoch, err)
	}
	member.Status = "active"
	member.Revision++
	raw, err = json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_membership SET payload=?,status='active',revision=? WHERE id=?`), string(raw), member.Revision, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='unexpected' WHERE principal_type='user' AND subject_id=?`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err == nil || epoch != 0 {
		t.Fatal("unknown policy mode reused old authority", epoch, err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_policy_migration SET policy_mode='v2' WHERE principal_type='user' AND subject_id=?`), actor.PrincipalID); err != nil {
		t.Fatal(err)
	}
	recovered, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run")
	if err != nil || recovered <= narrowed {
		t.Fatal("restored membership reused old capability epoch", recovered, err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	if epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err == nil || epoch != 0 {
		t.Fatal("storage outage returned warmed permission version", epoch, err)
	}
}
