package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

type countedPermissionReader struct {
	permissionReader
	queries int
}

func (r *countedPermissionReader) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	r.queries++
	return r.permissionReader.QueryRowContext(ctx, query, args...)
}
func (r *countedPermissionReader) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	r.queries++
	return r.permissionReader.QueryContext(ctx, query, args...)
}

func TestSQLPermissionSnapshotHeaderFreshFactsAndSingleRoundTrip(t *testing.T) {
	f := newAdministratorFixture(t)
	id := f.actors[2].PrincipalID
	reader := &countedPermissionReader{permissionReader: f.db}
	s, err := loadPermissionSnapshotHeader(f.ctx, reader, PrincipalUser, id)
	if err != nil || reader.queries != 1 || s.Principal.ID != id || !s.Principal.IsActive || s.Mode != "v2" ||
		len(s.Roles) == 0 || len(s.Memberships) != 1 || s.Memberships[0].SubjectID != id ||
		s.Bindings == nil || s.Delegations == nil || s.Grants == nil {
		t.Fatalf("fresh complete header: queries=%d value=%+v err=%v", reader.queries, s, err)
	}
	var expectedRoles []RoleDefinition
	rows, err := f.db.QueryContext(f.ctx, `SELECT payload FROM platform_identity_role_definition ORDER BY role_code,role_version`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var raw []byte
		var role RoleDefinition
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatal(err)
		}
		expectedRoles = append(expectedRoles, role)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedRoles, s.Roles) {
		t.Fatal("role contents/order changed")
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE,revision=revision+1 WHERE principal_type='user' AND id=?`), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_membership WHERE subject_id=?`), id); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id)
	if err != nil || after.Principal.IsActive || len(after.Memberships) != 0 || after.Principal.Revision <= s.Principal.Revision {
		t.Fatalf("new call used stale identity facts: %+v %v", after, err)
	}
	if _, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, "absent"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatal(err)
	}
}

func TestSQLPermissionSnapshotHeaderPreservesRepeatableReadAndRejectsCorruptFacts(t *testing.T) {
	f := newAdministratorFixture(t)
	id := f.actors[2].PrincipalID
	tx, err := f.db.BeginTx(f.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before, err := loadPermissionSnapshotHeader(f.ctx, tx, PrincipalUser, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE WHERE principal_type='user' AND id=?`), id); err != nil {
		t.Fatal(err)
	}
	within, err := loadPermissionSnapshotHeader(f.ctx, tx, PrincipalUser, id)
	if err != nil || !reflect.DeepEqual(before, within) {
		t.Fatal("transaction mixed snapshot generations", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id)
	if err != nil || after.Principal.IsActive {
		t.Fatal("new transaction failed to see revocation", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_membership SET payload='{"revision":"invalid"}' WHERE subject_id=?`), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PermissionSnapshot(f.ctx, PrincipalUser, id); err == nil {
		t.Fatal("corrupt current membership accepted")
	}
}
