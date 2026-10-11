package identity

import (
	"context"
	"encoding/json"
	"github.com/lexagent/platform/internal/sqlutil"
	"testing"
	"time"
)

func TestSQLAuthorizationEpochTracksNaturalV2BoundariesWithAlternativeAllow(t *testing.T) {
	f := newAdministratorFixture(t)
	s, actor := f.store, f.actors[2]
	scope := actor
	scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID = "installation-test", "installation-test", "fixture", "v1"
	app := ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}
	grantStart, grantExpiry := f.now.Add(time.Minute), f.now.Add(2*time.Minute)
	roleStart, roleExpiry := f.now.Add(3*time.Minute), f.now.Add(4*time.Minute)
	memberStart, memberExpiry := f.now.Add(5*time.Minute), f.now.Add(6*time.Minute)
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, binding := range []RoleBinding{
		{ID: "epoch-permanent-role", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixed"},
		{ID: "epoch-temporary-role", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "temporary", Validity: Validity{StartsAt: &roleStart, ExpiresAt: &roleExpiry}},
	} {
		if err := insertRoleBinding(f.ctx, tx, binding); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []Grant{
		{ID: "epoch-permanent-grant", SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: scope.AgentInstanceID, ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixed", DataScope: DataScope{Type: "owner"}},
		{ID: "epoch-temporary-grant", SubjectType: PrincipalUser, SubjectID: actor.PrincipalID, TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID, AgentInstanceID: scope.AgentInstanceID, ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "temporary", DataScope: DataScope{Type: "approved_organization"}, Validity: Validity{StartsAt: &grantStart, ExpiresAt: &grantExpiry}},
	} {
		if err := insertPermissionGrant(f.ctx, tx, grant, f.now); err != nil {
			t.Fatal(err)
		}
	}
	member := Membership{ID: "epoch-temporary-member", SubjectID: actor.PrincipalID, Scope: ManagementScope{Type: "department", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID}, Status: "active", Revision: 1, Validity: Validity{StartsAt: &memberStart, ExpiresAt: &memberExpiry}}
	raw, err := json.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,starts_at,expires_at,payload,scope_hash) VALUES(?,?,?,?,'','active',1,?,?,?,?)`), member.ID, actor.PrincipalID, actor.TenantID, actor.DepartmentID, memberStart, memberExpiry, string(raw), permissionHash([]byte(member.ID))); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cursor := f.now
	s.clock = func() time.Time { return cursor }
	for _, tc := range []struct {
		at    time.Time
		epoch uint64
	}{
		{f.now, 1}, {f.now.Add(30 * time.Second), 1}, {grantStart, 2}, {grantStart.Add(time.Second), 2}, {grantExpiry, 3}, {roleStart, 4}, {roleExpiry, 5}, {memberStart, 6}, {memberExpiry, 7},
	} {
		cursor = tc.at
		epoch, err := s.CurrentAuthorizationEpoch(f.ctx, scope, "run")
		if err != nil || epoch != tc.epoch {
			t.Fatalf("at=%v epoch=%d want=%d error=%v", cursor, epoch, tc.epoch, err)
		}
	}
	// No durable permission was rewritten: the permanent source still permits
	// new Runs, but an old execution context must fail its epoch equality check.
	var revision uint64
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), actor.PrincipalID).Scan(&revision); err != nil || revision != 1 {
		t.Fatal("natural expiry required a permission write", err)
	}
	restarted := NewSQLStore(f.db)
	restarted.clock = func() time.Time { return cursor }
	if epoch, err := restarted.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err != nil || epoch != 7 {
		t.Fatal("effective temporal state did not survive a store restart", epoch, err)
	}
	// Keep child admission's version fence open while a separate heartbeat
	// reads the same unchanged permission. Neither may require an UPDATE lock.
	held, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if epoch, err := restarted.CurrentAuthorizationEpochTx(f.ctx, held, scope, "run"); err != nil || epoch != 7 {
		t.Fatal("child admission version fence failed", epoch, err)
	}
	heartbeatCtx, cancelHeartbeat := context.WithTimeout(f.ctx, time.Second)
	defer cancelHeartbeat()
	if epoch, err := restarted.CurrentAuthorizationEpoch(heartbeatCtx, scope, "run"); err != nil || epoch != 7 {
		t.Fatal("unchanged heartbeat blocked behind child admission", epoch, err)
	}
}
