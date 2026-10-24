package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func continuityEpochFixture(t *testing.T) (administratorFixture, sharedkernel.Scope, time.Time) {
	t.Helper()
	f := newAdministratorFixture(t)
	scope := f.actors[2]
	scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID = "continuity-install", "continuity-install", "fixture", "v1"
	scope.SessionID, scope.RunID, scope.TraceID, scope.AuthorizationEpoch = "continuity-session", "continuity-run", "continuity-trace", 1
	app := ManagementScope{Type: "application", TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID}
	expiry := f.now.Add(time.Minute)
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertRoleBinding(f.ctx, tx, RoleBinding{ID: "continuity-role", SubjectID: scope.PrincipalID, RoleCode: "operator", RoleVersion: 1, Scope: app, Status: "active", Revision: 1, SourceID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	for _, temporary := range []bool{false, true} {
		grant := Grant{ID: "continuity-permanent", SubjectType: PrincipalUser, SubjectID: scope.PrincipalID, TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
			AgentInstanceID: scope.AgentInstanceID, ResourceType: "agent_installation", ResourceID: scope.AgentInstanceID, Action: "run", Effect: "allow", Status: "active", Revision: 1, SourceID: "fixture", DataScope: DataScope{Type: "owner"}}
		if temporary {
			grant.ID = "continuity-temporary"
			grant.ExpiresAt = &expiry
		}
		// Independent provenance makes these alternative grants distinct under
		// the real unique grant key; timestamps alone do not change that key.
		grant.SourceID = grant.ID
		if err := insertPermissionGrant(f.ctx, tx, grant, f.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return f, scope, expiry
}

func TestSQLContinuityAuthorizationDoesNotWaitBehindItsOwnQueuedWriter(t *testing.T) {
	f, scope, _ := continuityEpochFixture(t)
	if err := f.store.EnsureWorkloadBindingSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	const executor = "continuity-executor"
	if err := f.store.CreatePrincipal(f.ctx, Principal{Type: PrincipalServicePrincipal, ID: executor, TenantID: scope.TenantID, IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('service_principal',?,'v2',1,1)`), executor); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateMachineCredential(f.ctx, MachineCredential{TenantID: scope.TenantID, PrincipalID: executor,
		SecretHash: strings.Repeat("a", 64), NetworkCIDRs: []string{"127.0.0.1/32"}, Status: "active", Revision: 1}); err != nil {
		t.Fatal(err)
	}
	binding := WorkloadBinding{TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		InstallationID: scope.InstallationID, AgentID: scope.AgentID, AgentVersionID: scope.AgentVersionID,
		PrincipalID: executor, Status: "active", Revision: 1}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_workload_binding
		(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload)
		VALUES(?,?,?,?,?,?,?,?,?)`), workloadScopeHash(binding), binding.TenantID, binding.DepartmentID,
		binding.ApplicationID, binding.InstallationID, binding.PrincipalID, binding.Status, binding.Revision, string(bindingRaw)); err != nil {
		t.Fatal(err)
	}
	epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run")
	if err != nil || epoch != 1 {
		t.Fatal(epoch, err)
	}
	owner, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Rollback()
	if err := f.store.AcquirePermissionReadContinuity(f.ctx, owner); err != nil {
		t.Fatal(err)
	}
	writerCtx, stop := context.WithTimeout(f.ctx, 5*time.Second)
	defer stop()
	writer, err := f.db.BeginTx(writerCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	var pid int
	if err := writer.QueryRowContext(writerCtx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- lockPermissionContinuity(writerCtx, writer) }()
	t.Cleanup(func() {
		stop()
		owner.Rollback()
		writer.Rollback()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owned writer did not stop")
		}
	})
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := f.db.QueryRowContext(f.ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("writer never entered the actual lock queue")
		}
		time.Sleep(time.Millisecond)
	}
	readCtx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	bound := sqlutil.WithContinuityTransaction(readCtx, f.db, owner)
	resourceDenied := errors.New("owned resource denial")
	if err := f.store.WithCurrentAuthorizationSnapshot(bound, scope, "run", func(got uint64, snapshot PermissionSnapshot) error {
		if got != epoch || snapshot.Principal.ID != scope.PrincipalID {
			t.Error("wrong current authority")
		}
		return resourceDenied
	}); !errors.Is(err, resourceDenied) {
		t.Fatal("nested read waited behind its own queued writer", err)
	}
	resourceDeniedUnderContext := errors.New("resource denied after joined related reads")
	err = f.store.WithCurrentAuthorizationSnapshotContext(bound, scope, "run",
		func(readCtx context.Context, got uint64, snapshot PermissionSnapshot) error {
			if got != epoch || snapshot.Principal.ID != scope.PrincipalID {
				t.Error("wrong contextual current authority")
			}
			joinedSnapshot, readErr := f.store.PermissionSnapshot(readCtx, PrincipalUser, scope.PrincipalID)
			if readErr != nil || joinedSnapshot.Principal.ID != scope.PrincipalID {
				t.Error("related identity read failed to join the current authorization transaction", readErr)
			}
			joinedBinding, bindingErr := f.store.ResolveWorkloadIdentity(readCtx, scope)
			if bindingErr != nil || joinedBinding.PrincipalID != executor {
				t.Error("workload binding read failed to join the current authorization transaction", bindingErr)
			}
			joinedCredential, credentialErr := f.store.GetMachineCredential(readCtx, scope.TenantID, executor)
			if credentialErr != nil || joinedCredential.Status != "active" {
				t.Error("machine credential read failed to join the current authorization transaction", credentialErr)
			}
			return resourceDeniedUnderContext
		})
	if !errors.Is(err, resourceDeniedUnderContext) {
		t.Fatal("context-bound authorization read waited behind queued writer", err)
	}
	if got, err := f.store.CurrentAuthorizationEpoch(bound, scope, "run"); err != nil || got != epoch {
		t.Fatal(got, err)
	}
	if got, err := f.store.CurrentAuthorizationEpochTx(bound, owner, scope, "run"); err != nil || got != epoch {
		t.Fatal(got, err)
	}
	if snapshot, err := f.store.PermissionSnapshot(bound, PrincipalUser, scope.PrincipalID); err != nil || snapshot.Principal.ID != scope.PrincipalID {
		t.Fatal("snapshot opened a nested transaction", err)
	}
	var one int
	if err := owner.QueryRowContext(f.ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatal("IAM completed caller transaction", err)
	}
	if err := owner.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PermissionSnapshot(bound, PrincipalUser, scope.PrincipalID); !errors.Is(err, sql.ErrTxDone) {
		t.Fatal("closed owner escaped through fresh connection", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		done <- nil
	case <-writerCtx.Done():
		t.Fatal("writer remained blocked after owner rollback")
	}
}

func TestSQLContinuityAuthorizationCannotRollBackAnEpochObservation(t *testing.T) {
	f, scope, expiry := continuityEpochFixture(t)
	cursor := f.now
	f.store.clock = func() time.Time { return cursor }
	if epoch, err := f.store.CurrentAuthorizationEpoch(f.ctx, scope, "run"); err != nil || epoch != 1 {
		t.Fatal(epoch, err)
	}
	// Exercise the public captured-snapshot path before expiry. The protected
	// revalidation below must not reuse an earlier process-level snapshot.
	if err := f.store.WithCurrentAuthorizationSnapshot(f.ctx, scope, "run", func(uint64, PermissionSnapshot) error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]string{scope.TenantID, scope.DepartmentID, scope.ApplicationID, scope.AgentInstanceID, scope.InstallationID, scope.AgentID, scope.AgentVersionID, scope.PrincipalType, scope.PrincipalID, "run"})
	key := permissionHash(raw)
	owner, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Rollback()
	bound := sqlutil.WithContinuityTransaction(f.ctx, f.db, owner)
	if epoch, err := f.store.CurrentAuthorizationEpoch(bound, scope, "run"); err != nil || epoch != 1 {
		t.Fatal(epoch, err)
	}
	cursor = expiry
	called := false
	err = f.store.WithCurrentAuthorizationSnapshot(bound, scope, "run", func(uint64, PermissionSnapshot) error { called = true; return nil })
	if !errors.Is(err, ErrPermissionExplanationStale) || called {
		t.Fatal("expired source reused old epoch or invoked resource callback", err, called)
	}
	var stored uint64
	if err := owner.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT epoch FROM platform_identity_authorization_version WHERE scope_key=?`), key).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("business transaction advanced durable observation", stored, err)
	}
	if err := owner.Rollback(); err != nil {
		t.Fatal(err)
	}
	// Independent observation owns its commit even when a resource is denied.
	denied := errors.New("resource denied after epoch observation")
	err = f.store.WithCurrentAuthorizationSnapshot(f.ctx, scope, "run", func(epoch uint64, _ PermissionSnapshot) error {
		if epoch != 2 {
			t.Error("new temporal epoch missing", epoch)
		}
		return denied
	})
	if !errors.Is(err, denied) {
		t.Fatal(err)
	}
	if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT epoch FROM platform_identity_authorization_version WHERE scope_key=?`), key).Scan(&stored); err != nil || stored != 2 {
		t.Fatal("resource denial undid epoch observation", stored, err)
	}
	foreign := sqlutil.WithContinuityTransaction(f.ctx, new(sql.DB), owner)
	if _, err := f.store.CurrentAuthorizationEpoch(foreign, scope, "run"); err == nil {
		t.Fatal("foreign pool was ignored")
	}
}

func TestSQLContinuityCapturedSnapshotDoesNotHideRevocation(t *testing.T) {
	for _, mode := range []string{"principal", "grant"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, _ := continuityEpochFixture(t)
			if err := f.store.WithCurrentAuthorizationSnapshot(f.ctx, scope, "run", func(epoch uint64, _ PermissionSnapshot) error {
				if epoch != 1 {
					t.Fatal("unexpected initial epoch", epoch)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// A real writer's continuity lock precedes its source mutations.
			// Do not call an epoch observer afterward: that is the exact stale
			// persisted-version window the former process cache concealed.
			write, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer write.Rollback()
			if err := lockPermissionContinuity(f.ctx, write); err != nil {
				t.Fatal(err)
			}
			if mode == "principal" {
				_, err = write.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE,revision=revision+1 WHERE principal_type='user' AND id=?`), scope.PrincipalID)
			} else {
				_, err = write.ExecContext(f.ctx, `UPDATE platform_identity_grant SET status='revoked',revision=revision+1 WHERE id='continuity-permanent'`)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := write.Commit(); err != nil {
				t.Fatal(err)
			}
			read, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer read.Rollback()
			bound := sqlutil.WithContinuityTransaction(f.ctx, f.db, read)
			called := false
			err = f.store.WithCurrentAuthorizationSnapshot(bound, scope, "run", func(uint64, PermissionSnapshot) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("revoked source reached protected callback through an old captured snapshot", mode, err, called)
			}
		})
	}
}
