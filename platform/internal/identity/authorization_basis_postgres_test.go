package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// Independent original three-statement reader for the native equivalence
// oracle. The production implementation uses one fenced statement instead.
func originalAuthorizationBasisForTest(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, action string) (Principal, []Grant, []uint64, error) {
	p := Principal{ID: scope.PrincipalID, Type: PrincipalType(scope.PrincipalType), TenantID: scope.TenantID}
	var roles, groups string
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT roles_json,groups_json,active,revision FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? FOR SHARE`), scope.PrincipalType, scope.PrincipalID, scope.TenantID).Scan(&roles, &groups, &p.IsActive, &p.Revision); err != nil {
		return Principal{}, nil, nil, err
	}
	if json.Unmarshal([]byte(roles), &p.Roles) != nil || json.Unmarshal([]byte(groups), &p.Groups) != nil {
		return Principal{}, nil, nil, errors.New("identity principal data is invalid")
	}
	h := make([]uint64, 3)
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT t.revision,d.revision,a.revision FROM platform_identity_tenant t JOIN platform_identity_department d ON d.tenant_id=t.id JOIN platform_identity_application a ON a.tenant_id=t.id AND a.department_id=d.id WHERE t.id=? AND d.id=? AND a.id=? AND t.status='active' AND d.status='active' AND a.status='active' FOR SHARE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID).Scan(&h[0], &h[1], &h[2]); err != nil {
		return Principal{}, nil, nil, err
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id,tenant_id,department_id,application_id,agent_instance_id,subject_type,subject_id,action,effect,status,revision FROM platform_identity_grant WHERE tenant_id=? AND department_id=? AND application_id=? AND agent_instance_id=? AND subject_type=? AND subject_id=? AND action=? ORDER BY id FOR SHARE`), scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.PrincipalType, scope.PrincipalID, action)
	if err != nil {
		return Principal{}, nil, nil, err
	}
	defer rows.Close()
	g := []Grant{}
	for rows.Next() {
		var grant Grant
		if err := rows.Scan(&grant.ID, &grant.TenantID, &grant.DepartmentID, &grant.ApplicationID, &grant.AgentInstanceID, &grant.SubjectType, &grant.SubjectID, &grant.Action, &grant.Effect, &grant.Status, &grant.Revision); err != nil {
			return Principal{}, nil, nil, err
		}
		g = append(g, grant)
	}
	if err := rows.Err(); err != nil {
		return Principal{}, nil, nil, err
	}
	return p, g, h, nil
}

func TestSQLAuthorizationBasisMatchesOriginalFingerprintAndFreshRows(t *testing.T) {
	f, scope, _ := continuityEpochFixture(t)
	ctx := f.store.withPermissionDecode(f.ctx)
	read := func(scope sharedkernel.Scope, action string) string {
		t.Helper()
		tx, err := f.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := f.store.AcquirePermissionReadContinuity(ctx, tx); err != nil {
			t.Fatal(err)
		}
		p, g, h, err := readAuthorizationBasisTx(ctx, tx, scope, action)
		originalP, originalG, originalH, originalErr := originalAuthorizationBasisForTest(ctx, tx, scope, action)
		if (err == nil) != (originalErr == nil) {
			t.Fatalf("basis acceptance changed: %v / %v", err, originalErr)
		}
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) || !errors.Is(originalErr, sql.ErrNoRows) {
				t.Fatal("unexpected source error", err, originalErr)
			}
			return ""
		}
		if !reflect.DeepEqual(p, originalP) || !reflect.DeepEqual(g, originalG) || !reflect.DeepEqual(h, originalH) {
			t.Fatal("fresh native facts differ from original reader")
		}
		got, err := authorizationFingerprint(p, g, h)
		want, originalErr := authorizationFingerprint(originalP, originalG, originalH)
		if err != nil || originalErr != nil || got != want {
			t.Fatal("native projection changed the persisted epoch fingerprint")
		}
		return got
	}
	initial := read(scope, "run")
	if initial == "" || read(scope, "run") != initial {
		t.Fatal("warm decode changed authoritative identity")
	}
	if read(scope, "knowledge.search") == "" {
		t.Fatal("empty legacy grant set changed reader behavior")
	}
	for _, column := range []string{"principal", "application", "grant"} {
		var query string
		var arg any
		switch column {
		case "principal":
			query, arg = `UPDATE platform_identity_principal SET revision=revision+1 WHERE id=? AND principal_type='user'`, scope.PrincipalID
		case "application":
			query, arg = `UPDATE platform_identity_application SET revision=revision+1 WHERE id=?`, scope.ApplicationID
		case "grant":
			query, arg = `UPDATE platform_identity_grant SET revision=9007199254740991 WHERE id=?`, "continuity-permanent"
		}
		if _, err := f.db.ExecContext(ctx, sqlutil.Bind(query), arg); err != nil {
			t.Fatal(err)
		}
		next := read(scope, "run")
		if next == "" || next == initial {
			t.Fatal("fresh replacement bytes reused an old basis", column)
		}
		initial = next
	}
	missing := scope
	missing.PrincipalID = "missing-principal"
	read(missing, "run")
	missing = scope
	missing.ApplicationID = "missing-application"
	read(missing, "run")
	if _, err := f.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_department SET status='inactive' WHERE id=?`), scope.DepartmentID); err != nil {
		t.Fatal(err)
	}
	if read(scope, "run") != "" {
		t.Fatal("inactive hierarchy accepted")
	}
}

func TestSQLAuthorizationBasisKeepsEverySourceShareLocked(t *testing.T) {
	f, scope, _ := continuityEpochFixture(t)
	reader, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	if _, _, _, err := readAuthorizationBasisTx(f.ctx, reader, scope, "run"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ query, id string }{
		{`SELECT 1 FROM platform_identity_principal WHERE id=? AND principal_type='user' FOR UPDATE NOWAIT`, scope.PrincipalID},
		{`SELECT 1 FROM platform_identity_tenant WHERE id=? FOR UPDATE NOWAIT`, scope.TenantID},
		{`SELECT 1 FROM platform_identity_department WHERE id=? FOR UPDATE NOWAIT`, scope.DepartmentID},
		{`SELECT 1 FROM platform_identity_application WHERE id=? FOR UPDATE NOWAIT`, scope.ApplicationID},
		{`SELECT 1 FROM platform_identity_grant WHERE id=? FOR UPDATE NOWAIT`, "continuity-permanent"},
		{`SELECT 1 FROM platform_identity_grant WHERE id=? FOR UPDATE NOWAIT`, "continuity-temporary"},
	} {
		writer, err := f.db.BeginTx(f.ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var value int
		err = writer.QueryRowContext(f.ctx, sqlutil.Bind(target.query), target.id).Scan(&value)
		writer.Rollback()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("source SHARE fence missing: %s, %v", target.id, err)
		}
	}
	// Unrelated identities remain independently writable.
	writer, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	var value int
	if err := writer.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_principal WHERE id=? AND principal_type='user' FOR UPDATE NOWAIT`), f.actors[0].PrincipalID).Scan(&value); err != nil {
		t.Fatal("basis read serialized unrelated principals", err)
	}
}

func TestSQLAuthorizationBasisLocksPrincipalBeforeHierarchyAndGrants(t *testing.T) {
	f, scope, _ := continuityEpochFixture(t)
	ctx, stop := context.WithTimeout(f.ctx, 5*time.Second)
	defer stop()
	blocker, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	var value int
	if err := blocker.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_identity_principal WHERE id=? AND principal_type='user' FOR UPDATE`), scope.PrincipalID).Scan(&value); err != nil {
		t.Fatal(err)
	}
	reader, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var pid int
	if err := reader.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, _, err := readAuthorizationBasisTx(ctx, reader, scope, "run")
		done <- err
	}()
	t.Cleanup(func() {
		stop()
		blocker.Rollback()
		reader.Rollback()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	for {
		var blocked bool
		if err := f.db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-done:
			t.Fatal("basis read did not wait on the principal fence", err)
		case <-ctx.Done():
			t.Fatal("principal wait was not observed")
		case <-time.After(5 * time.Millisecond):
		}
	}
	observer, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Rollback()
	for _, target := range []struct{ query, id string }{
		{`SELECT 1 FROM platform_identity_application WHERE id=? FOR UPDATE NOWAIT`, scope.ApplicationID},
		{`SELECT 1 FROM platform_identity_grant WHERE id=? FOR UPDATE NOWAIT`, "continuity-permanent"},
	} {
		if err := observer.QueryRowContext(ctx, sqlutil.Bind(target.query), target.id).Scan(&value); err != nil {
			t.Fatal("basis read acquired a later fence before the principal", err)
		}
	}
	observer.Rollback()
	blocker.Rollback()
	if err := <-done; err != nil {
		t.Fatal("basis read failed after releasing the principal", err)
	}
	// Leave the completed read in the channel for deterministic cleanup.
	done <- nil
}
