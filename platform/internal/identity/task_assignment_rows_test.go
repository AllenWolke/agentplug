package identity

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestTaskAssignmentRowsPreserveNativeFacts(t *testing.T) {
	raw := []byte(`[{"id":"native","subject_id":"owner","task_id":"task","action":"business.review","tenant_id":"tenant","department_id":"department","application_id":"application","agent_instance_id":"install","status":"revoked","revision":9,"payload":{"id":"forged","subject_id":"foreign","status":"active","revision":1,"source_id":"source","delegation_id":"delegation","expires_at":"2026-10-16T00:00:00Z","task_object":{"id":"task","owner_id":"creator"}}}]`)
	rows, err := parseTaskAssignmentRows(raw)
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	v := rows[0]
	if v.ID != "native" || v.SubjectID != "owner" || v.TaskID != "task" || v.Status != "revoked" || v.Revision != 9 ||
		v.Scope != (ManagementScope{Type: "agent_installation", TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", ResourceID: "install"}) ||
		v.SourceID != "source" || v.DelegationID != "delegation" || v.ExpiresAt == nil || v.TaskObject == nil || v.TaskObject.OwnerID != "creator" {
		t.Fatal("JSON overrode native assignment facts", v)
	}
	for _, invalid := range []string{`[{"payload":[]}]`, `[{"revision":"wrong","payload":{}}]`, `[{}]`, `[] trailing`} {
		if _, err := parseTaskAssignmentRows([]byte(invalid)); err == nil {
			t.Fatal("corrupt assignment accepted", invalid)
		}
	}
	empty, err := parseTaskAssignmentRows([]byte(`[]`))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
}

func TestSQLPermissionSnapshotCompleteFactsInOneStatement(t *testing.T) {
	f := newAdministratorFixture(t)
	id := f.actors[2].PrincipalID
	assignment := TaskAssignment{ID: "combined-read", SubjectID: id, TaskID: "task", Action: "business.review",
		Scope:  ManagementScope{Type: "agent_installation", TenantID: f.actors[2].TenantID, DepartmentID: f.actors[2].DepartmentID, ApplicationID: f.actors[2].ApplicationID, ResourceID: "installation"},
		Status: "active", Revision: 1, SourceID: "fixture", TaskObject: &DataObject{ID: "task", OwnerID: "creator"}}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertTaskAssignment(f.ctx, tx, assignment); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	reader := &countedPermissionReader{permissionReader: f.db}
	snapshot, err := loadPermissionSnapshot(f.ctx, reader, PrincipalUser, id)
	if err != nil || reader.queries != 1 {
		t.Fatalf("complete snapshot queries=%d err=%v", reader.queries, err)
	}
	assignments, err := loadTaskAssignments(f.ctx, f.db, id)
	if err != nil || len(assignments) != 1 || !reflect.DeepEqual(snapshot.Assignments, assignments) {
		t.Fatal("assignment projection changed", err)
	}
	var raw []byte
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT COALESCE(json_agg(row_to_json(g) ORDER BY g.id),'[]'::json) FROM platform_identity_grant g WHERE subject_type=? AND subject_id=?`), PrincipalUser, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	grants, err := parsePermissionGrantRows(raw)
	if err != nil || !reflect.DeepEqual(snapshot.Grants, grants) {
		t.Fatal("grant projection changed", err)
	}
	// A concurrent committed update must not alter a repeatable-read view;
	// the next public call must observe it, including authoritative columns.
	view, err := f.db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer view.Rollback()
	before, err := loadPermissionSnapshot(f.ctx, view, PrincipalUser, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `UPDATE platform_identity_task_assignment SET status='revoked',revision=revision+1 WHERE id='combined-read'`); err != nil {
		t.Fatal(err)
	}
	within, err := loadPermissionSnapshot(f.ctx, view, PrincipalUser, id)
	if err != nil || !reflect.DeepEqual(before, within) {
		t.Fatal("mixed MVCC views", err)
	}
	if err := view.Commit(); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id)
	if err != nil || after.Assignments[0].Status != "revoked" || after.Assignments[0].Revision != 2 {
		t.Fatal("new call reused old facts", err)
	}
	bad, _ := json.Marshal(map[string]any{"task_object": 3})
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_task_assignment SET payload=? WHERE id='combined-read'`), string(bad)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id); err == nil {
		t.Fatal("corrupt current assignment accepted")
	}
}
