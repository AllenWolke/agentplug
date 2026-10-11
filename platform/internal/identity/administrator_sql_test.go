package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

type administratorFixture struct {
	store    *SQLStore
	db       *sql.DB
	ctx      context.Context
	actors   []sharedkernel.Scope
	bindings []string
	now      time.Time
}

func newAdministratorFixture(t *testing.T) administratorFixture {
	t.Helper()
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture not configured")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config.Database, "test") && !strings.Contains(config.Database, "fixture") {
		t.Fatal("administrator integration requires an explicitly isolated test database")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	fixtureDatabase := fmt.Sprintf("administrator_fixture_%d", time.Now().UnixNano())
	if _, err := control.Exec(sqlutil.Bind("CREATE DATABASE \"" + fixtureDatabase + "\"")); err != nil {
		control.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// This exact generated name was created above; never drop the configured DB.
		if _, err := control.Exec(sqlutil.Bind("DROP DATABASE \"" + fixtureDatabase + "\"")); err != nil {
			t.Error(err)
		}
		control.Close()
	})
	config.Database = fixtureDatabase
	db := stdlib.OpenDB(*config)
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	s := NewSQLStore(db)
	s.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("admin-%d", time.Now().UnixNano())
	tenant, dept, app := prefix, prefix+"-d", prefix+"-a"
	for _, err := range []error{
		s.CreateTenant(ctx, Tenant{ID: tenant, Code: tenant, Name: "fixture", Status: "active", Revision: 1}),
		s.CreateDepartment(ctx, Department{ID: dept, TenantID: tenant, Code: dept, Name: "fixture", Status: "active", Revision: 1}),
		s.CreateApplication(ctx, Application{ID: app, TenantID: tenant, DepartmentID: dept, Code: app, Name: "fixture", Status: "active", Revision: 1}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	hash, err := hashEnrollmentPassword("fixture-administrator-password")
	if err != nil {
		t.Fatal(err)
	}
	f := administratorFixture{store: s, db: db, ctx: ctx, now: time.Now().UTC().Truncate(time.Microsecond)}
	s.clock = func() time.Time { return f.now }
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("%s-u%d", prefix, i)
		if err := s.CreatePrincipal(ctx, Principal{Type: PrincipalUser, ID: id, TenantID: tenant, IsActive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_local_credential(principal_id,tenant_id,department_id,application_id,display_name,password_hash,auth_revision,active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,TRUE,clock_timestamp(),clock_timestamp())`), id, tenant, dept, app, "fixture", hash); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), id); err != nil {
			t.Fatal(err)
		}
		m := Membership{ID: id + "-member", SubjectID: id, Scope: ManagementScope{Type: "application", TenantID: tenant, DepartmentID: dept, ApplicationID: app}, Status: "active", Revision: 1}
		raw, _ := json.Marshal(m)
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_membership(id,subject_id,tenant_id,department_id,application_id,status,revision,payload,scope_hash) VALUES(?,?,?,?,?,'active',1,?,?)`), m.ID, id, tenant, dept, app, string(raw), permissionHash([]byte(m.ID))); err != nil {
			t.Fatal(err)
		}
		if i < 2 {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			b := RoleBinding{ID: id + "-super", SubjectID: id, RoleCode: "super_admin", RoleVersion: 1, Scope: ManagementScope{Type: "global"}, Status: "active", Revision: 1, SourceID: "fixture"}
			if err := insertRoleBinding(ctx, tx, b); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			f.bindings = append(f.bindings, b.ID)
		}
		f.actors = append(f.actors, sharedkernel.Scope{TenantID: tenant, DepartmentID: dept, ApplicationID: app, PrincipalType: "user", PrincipalID: id})
	}
	return f
}

func (f administratorFixture) command(subject int, key string) AdministratorCommand {
	return AdministratorCommand{SubjectID: f.actors[subject].PrincipalID, ExpectedRevision: 1, IdempotencyKey: key, Reason: "authenticated administrator appointment", RoleCode: "permission_admin", Scope: ManagementScope{Type: "application", TenantID: f.actors[subject].TenantID, DepartmentID: f.actors[subject].DepartmentID, ApplicationID: f.actors[subject].ApplicationID}}
}

func (f administratorFixture) authenticate(t *testing.T, actor int, command AdministratorCommand) AdministratorCommand {
	t.Helper()
	digest, err := AdministratorCommandDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := f.store.CreateLocalStepUp(f.ctx, f.actors[actor], StepUpRequest{CurrentPassword: "fixture-administrator-password", Action: "administrator.appoint", RequestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	command.StepUpToken = proof.Token
	return command
}

func TestSQLAdministratorAuthenticationAndContinuity(t *testing.T) {
	t.Run("password and exact command binding", func(t *testing.T) {
		f := newAdministratorFixture(t)
		command := f.command(2, "bind")
		digest, _ := AdministratorCommandDigest(command)
		if _, err := f.store.CreateLocalStepUp(f.ctx, f.actors[0], StepUpRequest{CurrentPassword: "wrong", Action: "administrator.appoint", RequestDigest: digest}); !errors.Is(err, ErrCurrentPasswordInvalid) {
			t.Fatal(err)
		}
		command = f.authenticate(t, 0, command)
		changed := command
		changed.Reason = "tampered"
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], changed); !errors.Is(err, ErrStepUpRequired) {
			t.Fatal("unbound proof accepted", err)
		}
		receipt, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Revision != 2 || receipt.Command.StepUpToken != "" {
			t.Fatal("invalid receipt")
		}
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); err != nil {
			t.Fatal("idempotent retry denied", err)
		}
		changed.IdempotencyKey = command.IdempotencyKey
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], changed); !errors.Is(err, ErrIdentityConflict) {
			t.Fatal("retry mismatch accepted", err)
		}
		replay := f.command(1, "another")
		replay.StepUpToken = command.StepUpToken
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], replay); !errors.Is(err, ErrStepUpRequired) {
			t.Fatal("used proof accepted", err)
		}
	})
	t.Run("audit rollback preserves proof and principal revision", func(t *testing.T) {
		f := newAdministratorFixture(t)
		command := f.authenticate(t, 0, f.command(2, "rollback"))
		fault := errors.New("audit failure")
		f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return fault })
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); !errors.Is(err, fault) {
			t.Fatal(err)
		}
		var used bool
		var revision uint64
		if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT used FROM platform_identity_step_up WHERE token_hash=?`), refreshHash(command.StepUpToken)).Scan(&used); err != nil || used {
			t.Fatal("proof consumed on rollback", err)
		}
		if err := f.db.QueryRowContext(f.ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE id=?`), command.SubjectID).Scan(&revision); err != nil || revision != 1 {
			t.Fatal("partial revision", err)
		}
		f.store.SetAdministrativeRecorder(func(context.Context, *sql.Tx, sharedkernel.Scope, AdministrativeEvent) error { return nil })
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("password rotation and exact expiration invalidate proof", func(t *testing.T) {
		f := newAdministratorFixture(t)
		command := f.authenticate(t, 0, f.command(2, "expiry"))
		f.store.clock = func() time.Time { return f.now.Add(StepUpLifetime) }
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); !errors.Is(err, ErrStepUpRequired) {
			t.Fatal("expiry accepted", err)
		}
		f.store.clock = func() time.Time { return f.now }
		if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_local_credential SET auth_revision=auth_revision+1 WHERE principal_id=?`), f.actors[0].PrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AppointAdministrator(f.ctx, f.actors[0], command); !errors.Is(err, ErrStepUpRequired) {
			t.Fatal("stale credential accepted", err)
		}
	})
	t.Run("two administrators concurrently resign retain one permanent login", func(t *testing.T) {
		f := newAdministratorFixture(t)
		commands := make([]AdministratorCommand, 2)
		for i := 0; i < 2; i++ {
			commands[i] = AdministratorCommand{SubjectID: f.actors[i].PrincipalID, ExpectedRevision: 1, IdempotencyKey: fmt.Sprintf("resign-%d", i), Reason: "resign", RevokeBindingIDs: []string{f.bindings[i]}}
			commands[i] = f.authenticate(t, i, commands[i])
		}
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := f.store.AppointAdministrator(f.ctx, f.actors[i], commands[i])
				results <- err
			}(i)
		}
		wg.Wait()
		close(results)
		ok, protected := 0, 0
		for err := range results {
			if err == nil {
				ok++
			} else if errors.Is(err, ErrLastAdministrator) {
				protected++
			} else {
				t.Fatal(err)
			}
		}
		if ok != 1 || protected != 1 {
			t.Fatal("concurrent last administrator violation", ok, protected)
		}
	})
}
