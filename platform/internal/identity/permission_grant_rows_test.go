package identity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestPermissionGrantRowsAuthoritativeColumnsAndMutationIsolation(t *testing.T) {
	ctx := context.WithValue(context.Background(), permissionDecodeKey{}, newPermissionDecodeCache())
	raw := []byte(`[{"id":"actual","subject_id":"owner","action":"run","status":"revoked","revision":7,"permission_json":{"id":"forged","subject_id":"foreign","action":"publish.approve","status":"active","revision":1,"resource_id":"install","data_scope":{"type":"explicit_set","ids":["one"]},"expires_at":"2026-10-15T01:00:00Z"}}]`)
	rows, err := decodePermissionGrantRows(ctx, raw)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	g := rows[0]
	if g.ID != "actual" || g.SubjectID != "owner" || g.Action != "run" || g.Status != "revoked" || g.Revision != 7 || g.ResourceID != "install" {
		t.Fatal(g)
	}
	rows[0].DataScope.IDs[0] = "poison"
	*rows[0].ExpiresAt = rows[0].ExpiresAt.AddDate(1, 0, 0)
	fresh, err := decodePermissionGrantRows(ctx, raw)
	if err != nil || fresh[0].DataScope.IDs[0] != "one" || fresh[0].ExpiresAt.Year() != 2026 {
		t.Fatal(fresh, err)
	}
	changed, err := decodePermissionGrantRows(ctx, []byte(`[{"id":"actual","status":"disabled","revision":8,"permission_json":null}]`))
	if err != nil || changed[0].Status != "disabled" || changed[0].Revision != 8 {
		t.Fatal(changed, err)
	}
}

func TestPermissionGrantRowsEmptyAndCorruptProjection(t *testing.T) {
	rows, err := parsePermissionGrantRows([]byte(`[]`))
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	for _, raw := range []string{`[{"permission_json":[]}]`, `[{"revision":"wrong"}]`, `[] trailing`} {
		if _, err := parsePermissionGrantRows([]byte(raw)); err == nil {
			t.Fatal("corrupt projection accepted", raw)
		}
	}
}

func TestSQLPermissionSnapshotHeaderGrantColumnsAndRevocation(t *testing.T) {
	f := newAdministratorFixture(t)
	actor := f.actors[2]
	g := Grant{ID: "projection-grant", SubjectType: PrincipalUser, SubjectID: actor.PrincipalID,
		TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID,
		AgentInstanceID: "installation", ResourceType: "agent_installation", ResourceID: "installation",
		Action: "run", Effect: "allow", Status: "active", Revision: 1, DataScope: DataScope{Type: "owner"}, SourceID: "fixture"}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertPermissionGrant(f.ctx, tx, g, f.now); err != nil {
		t.Fatal(err)
	}
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "projection-operator", SubjectID: actor.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil || len(before.Grants) != 1 || before.Grants[0].Status != "active" {
		t.Fatal(before, err)
	}
	query := PermissionQuery{Action: "run", Scope: ManagementScope{Type: "application", TenantID: actor.TenantID, DepartmentID: actor.DepartmentID, ApplicationID: actor.ApplicationID}, ResourceType: "agent_installation", ResourceID: "installation"}
	for i := 0; i < 2; i++ {
		decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, actor.PrincipalID, query)
		if err != nil || !decision.Allowed {
			t.Fatal("active grant denied before revocation", decision, err)
		}
	}
	metadata := g
	metadata.SubjectID, metadata.Action, metadata.Status = "forged", "publish.approve", "active"
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET status='revoked',revision=2,permission_json=? WHERE id=?`), string(raw), g.ID); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID)
	if err != nil || len(after.Grants) != 1 || after.Grants[0].Status != "revoked" || after.Grants[0].Revision != 2 || after.Grants[0].SubjectID != actor.PrincipalID || after.Grants[0].Action != "run" {
		t.Fatal(after, err)
	}
	decision, err := f.store.ResolvePermission(f.ctx, PrincipalUser, actor.PrincipalID, query)
	if err != nil || decision.Allowed {
		t.Fatal("cached parsing retained revoked authority", decision, err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_grant SET permission_json='[]' WHERE id=?`), g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, actor.PrincipalID); err == nil {
		t.Fatal("corrupt current permission metadata accepted")
	}
}
