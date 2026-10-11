package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/schemaversion"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestFirstAdministratorPostgres(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("explicit isolated first-administrator fixture DSN required")
	}
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid fixture DSN")
	}
	if parsed.Host != "127.0.0.1" || parsed.Database != "knowledge_test" {
		t.Fatal("fixture must be the explicit local isolated database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	databaseName := "first_admin_fixture_" + time.Now().UTC().Format("20060102_150405_000000000")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+databaseName+`"`); err != nil {
		t.Fatal("create owned first-administrator database", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupCtx, `DROP DATABASE "`+databaseName+`" WITH (FORCE)`); err != nil {
			t.Errorf("drop owned first-administrator database: %v", err)
		}
	})
	isolatedURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("fixture URL invalid")
	}
	isolatedURL.Path = "/" + databaseName
	isolatedDSN := isolatedURL.String()
	// Run the real versioned migration command against this test-owned database.
	// The shared fixture DSN is only the maintenance connection and may contain
	// rows from other packages in the same integration batch.
	migrate := exec.CommandContext(ctx, "go", "run", "./cmd/migrate")
	migrate.Dir = "../.."
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		if key == "DB_DSN" || key == "DB_DRIVER" || key == "APP_ENV" || key == "PLATFORM_DEV_RUNTIME_PASSWORD" {
			continue
		}
		migrate.Env = append(migrate.Env, entry)
	}
	migrate.Env = append(migrate.Env, "APP_ENV=test", "DB_DRIVER=pgx", "DB_DSN="+isolatedDSN, "PLATFORM_DEV_RUNTIME_PASSWORD=")
	var migrationOutput, migrationDiagnostics bytes.Buffer
	migrate.Stdout, migrate.Stderr = &migrationOutput, &migrationDiagnostics
	if err := migrate.Run(); err != nil {
		output := strings.ReplaceAll(migrationOutput.String()+migrationDiagnostics.String(), isolatedDSN, "[redacted isolated DSN]")
		t.Fatalf("migrate owned first-administrator database: %T %s", err, output)
	}
	parsed.Database = databaseName
	owner, err := sqlutil.OpenPostgres(ctx, isolatedDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if err := schemaversion.Check(ctx, owner); err != nil {
		t.Fatal("run the actual platform migration before this test")
	}
	for _, table := range []string{"platform_identity_tenant", "platform_identity_department", "platform_identity_application", "platform_identity_principal", "platform_identity_oidc_binding", "platform_audit_event", "platform_notification_outbox"} {
		var count int
		if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT COUNT(*) FROM "+table)).Scan(&count); err != nil || count != 0 {
			t.Fatal("fixture must contain no identity/audit/outbox data")
		}
	}
	config := fixtureConfiguration(t)
	config.DBDSN = isolatedDSN
	runtimeDSN, err := pgx.ParseConfig(config.DBDSN)
	if err != nil {
		t.Fatal(err)
	}
	user := databaseName + "_dml"
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(runtimeDSN.Password) {
		t.Fatal("fixture password must be generated hexadecimal")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind(`CREATE ROLE "`+user+`" LOGIN PASSWORD '`+runtimeDSN.Password+`'`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(sqlutil.Bind(`DROP OWNED BY "` + user + `"`))
		if _, err := owner.Exec(sqlutil.Bind(`DROP ROLE "` + user + `"`)); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		`REVOKE TEMP ON DATABASE "` + databaseName + `" FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE "` + databaseName + `" TO "` + user + `"`,
		`GRANT USAGE ON SCHEMA public,knowledge TO "` + user + `"`,
		`GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public,knowledge TO "` + user + `"`,
		`REVOKE INSERT,UPDATE,DELETE ON platform_schema_version FROM "` + user + `"`,
		`GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public,knowledge TO "` + user + `"`,
	} {
		if _, err := owner.ExecContext(ctx, sqlutil.Bind(statement)); err != nil {
			t.Fatal(err)
		}
	}
	restrictBootstrapRuntimeFixture(t, ctx, owner, user)
	runtimeURL, err := url.Parse(isolatedDSN)
	if err != nil {
		t.Fatal("fixture URL invalid")
	}
	runtimeURL.User = url.UserPassword(user, runtimeDSN.Password)
	config.DBDSN = runtimeURL.String()
	dml, err := sqlutil.OpenPostgres(ctx, config.DBDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer dml.Close()
	verifyBootstrapRuntimeFixture(t, ctx, dml)
	store := identity.NewSQLStore(dml)
	invoke := func(c configuration) error {
		raw, err := json.Marshal(c)
		if err != nil {
			return err
		}
		var output bytes.Buffer
		err = run(ctx, []string{"--config", writeConfig(t, raw)}, &output)
		if err == nil && output.String() != "FIRST ADMINISTRATOR BOOTSTRAP PASS\n" {
			return errors.New("missing command success output")
		}
		return err
	}
	assertEmpty := func() {
		t.Helper()
		for _, table := range []string{"platform_identity_tenant", "platform_identity_department", "platform_identity_application", "platform_identity_principal", "platform_identity_oidc_binding", "platform_identity_membership", "platform_identity_role_binding", "platform_identity_policy_migration", "platform_audit_event", "platform_notification_outbox"} {
			var count int
			if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT COUNT(*) FROM "+table)).Scan(&count); err != nil || count != 0 {
				t.Fatalf("failed initialization left rows in %s", table)
			}
		}
	}
	if err := store.InitializeFirstAdministrator(ctx, config.FirstAdministratorRequest, verifyFirstAdministratorDatabase, nil); err == nil {
		t.Fatal("missing audit recorder accepted")
	}
	assertEmpty()
	if err := store.InitializeFirstAdministrator(ctx, config.FirstAdministratorRequest, nil, func(context.Context, *sql.Tx, identity.FirstAdministratorRequest, time.Time) error { return nil }); err == nil {
		t.Fatal("missing schema/privilege verifier accepted")
	}
	assertEmpty()
	if err := identity.NewSQLStore(owner).InitializeFirstAdministrator(ctx, config.FirstAdministratorRequest, verifyFirstAdministratorDatabase, func(context.Context, *sql.Tx, identity.FirstAdministratorRequest, time.Time) error { return nil }); err == nil {
		t.Fatal("DDL/root account accepted")
	}
	assertEmpty()
	if _, err := owner.ExecContext(ctx, sqlutil.Bind(`CREATE FUNCTION fixture_fail_bootstrap_outbox_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic outbox failure'; END $$; CREATE TRIGGER fixture_fail_bootstrap_outbox BEFORE INSERT ON platform_notification_outbox FOR EACH ROW EXECUTE FUNCTION fixture_fail_bootstrap_outbox_fn()`)); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("outbox failure accepted")
	}
	assertEmpty()
	if _, err := owner.ExecContext(ctx, sqlutil.Bind(`DROP TRIGGER fixture_fail_bootstrap_outbox ON platform_notification_outbox; DROP FUNCTION fixture_fail_bootstrap_outbox_fn()`)); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("INSERT INTO platform_identity_tenant(id,code,name,status,revision,created_at) VALUES ('fixture-partial','fixture-partial','Partial fixture','active',1,clock_timestamp())")); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("partially initialized identity accepted")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("DELETE FROM platform_identity_tenant WHERE id='fixture-partial'")); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("INSERT INTO platform_schema_version(version,checksum,applied_at) VALUES (?,?,clock_timestamp())"), schemaversion.CurrentVersion+1, schemaversion.CurrentChecksum()); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("future platform schema accepted")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("DELETE FROM platform_schema_version WHERE version=?"), schemaversion.CurrentVersion+1); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	// unrelated views must not be treated as nontransactional IAM tables.
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("CREATE TABLE platform_identity_unregistered_fixture (id INT PRIMARY KEY)")); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("unregistered IAM table accepted through prefix")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("DROP TABLE platform_identity_unregistered_fixture")); err != nil {
		t.Fatal(err)
	}
	assertEmpty()
	// The managed-department and batch tables belong to IAM. Their empty
	// schema is permitted, but any existing fact must still prevent bootstrap.
	for _, fixture := range []struct {
		name    string
		insert  string
		cleanup string
	}{
		{"department-policy", `INSERT INTO platform_identity_department_agent_policy(tenant_id,department_id,revision,entries_digest,updated_by,updated_at) VALUES('fixture-existing','fixture-department',1,repeat('b',64),'fixture-owner',clock_timestamp())`, `DELETE FROM platform_identity_department_agent_policy WHERE tenant_id='fixture-existing' AND department_id='fixture-department'`},
		{"department-entry", `INSERT INTO platform_identity_department_agent_policy(tenant_id,department_id,revision,entries_digest,updated_by,updated_at) VALUES('fixture-existing','fixture-department',1,repeat('b',64),'fixture-owner',clock_timestamp()); INSERT INTO platform_identity_department_agent_entry(tenant_id,department_id,application_id,installation_id,actions_json,action_versions_json) VALUES('fixture-existing','fixture-department','fixture-application','fixture-installation','["run"]','{"run":1}')`, `DELETE FROM platform_identity_department_agent_entry WHERE tenant_id='fixture-existing' AND department_id='fixture-department'; DELETE FROM platform_identity_department_agent_policy WHERE tenant_id='fixture-existing' AND department_id='fixture-department'`},
		{"department-change", `INSERT INTO platform_identity_department_agent_change(idempotency_key,request_digest,actor_id,tenant_id,department_id,receipt_json,occurred_at) VALUES('fixture-existing-change',repeat('b',64),'fixture-owner','fixture-existing','fixture-department','{}',clock_timestamp())`, `DELETE FROM platform_identity_department_agent_change WHERE idempotency_key='fixture-existing-change'`},
		{"permission-batch", `INSERT INTO platform_identity_permission_batch(id,actor_id,actor_tenant_id,tenant_id,request_digest,payload,created_at,updated_at) VALUES('fixture-existing-batch','fixture-owner','fixture-existing','fixture-existing',repeat('b',64),'{}',clock_timestamp(),clock_timestamp())`, `DELETE FROM platform_identity_permission_batch WHERE id='fixture-existing-batch'`},
	} {
		t.Run("existing-"+fixture.name+"-blocks-bootstrap", func(t *testing.T) {
			if _, err := owner.ExecContext(ctx, fixture.insert); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := owner.ExecContext(ctx, fixture.cleanup); err != nil {
					t.Fatal(err)
				}
			}()
			if err := invoke(config); err == nil {
				t.Fatal("existing IAM fact allowed empty-store bootstrap")
			}
			assertEmpty()
		})
	}
	assertEmpty()
	// Registered execution identities still count as existing IAM data. Adding
	// their tables to the explicit registry must not bypass empty-store safety.
	if _, err := owner.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_workload_binding(scope_hash,tenant_id,department_id,application_id,installation_id,principal_id,status,revision,payload) VALUES(?, 'existing-tenant','existing-department','existing-application','existing-installation','existing-machine','active',1,'{}')`), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("existing workload binding allowed empty-store bootstrap")
	}
	assertEmpty()
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("DELETE FROM platform_identity_workload_binding WHERE scope_hash=?"), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("CREATE VIEW fixture_unrelated_view AS SELECT 1 AS value")); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec(sqlutil.Bind("DROP VIEW fixture_unrelated_view"))
	var wait sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, principal := range []string{"first.admin", "other.admin"} {
		candidate := config
		candidate.PrincipalID = principal
		wait.Add(1)
		go func() { defer wait.Done(); <-start; results <- invoke(candidate) }()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent initialization successes = %d, want 1", successes)
	}
	resolved, err := store.ResolveOIDC(ctx, config.Issuer, config.Subject)
	if err != nil || resolved.TenantID != config.TenantID || resolved.DepartmentID != config.DepartmentID || resolved.ApplicationID != config.ApplicationID || len(resolved.Roles) != 0 {
		t.Fatal("initial OIDC identity does not resolve approved scope and roles")
	}
	snapshot, err := store.PermissionSnapshot(ctx, identity.PrincipalUser, resolved.Username)
	if err != nil || snapshot.Mode != "v2" || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].RoleCode != "super_admin" || snapshot.Bindings[0].Scope.Type != "global" || snapshot.Bindings[0].ExpiresAt != nil || len(snapshot.Memberships) != 1 || len(snapshot.Grants) != 0 {
		t.Fatal("first administrator has incorrect versioned authority", err)
	}
	t.Run("read-only inventory CLI", func(t *testing.T) {
		command := exec.CommandContext(ctx, "go", "run", "./cmd/identity-inspect")
		command.Dir = "../.."
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "DB_DSN=") {
				command.Env = append(command.Env, entry)
			}
		}
		command.Env = append(command.Env, "DB_DSN="+config.DBDSN)
		var output, diagnostics bytes.Buffer
		command.Stdout = &output
		command.Stderr = &diagnostics
		if err := command.Run(); err != nil {
			t.Fatalf("actual inventory CLI failed: %T", err)
		}
		var inventory identity.PermissionInventory
		if err := json.Unmarshal(output.Bytes(), &inventory); err != nil || len(inventory.Items) != 1 || inventory.Items[0].Principal.ID != resolved.Username || inventory.Items[0].ActiveOIDCBindings != 1 || inventory.Items[0].LocalCredentialActive {
			t.Fatal("actual inventory CLI returned incorrect identity facts")
		}
		for _, secret := range []string{config.DBDSN, runtimeDSN.Password, config.Issuer, config.Subject} {
			if strings.Contains(output.String()+diagnostics.String(), secret) {
				t.Fatal("actual inventory CLI leaked private authentication facts")
			}
		}
	})

	if _, err := store.ResolveOIDC(ctx, config.Issuer, config.Subject+"-unbound"); !errors.Is(err, identity.ErrOIDCBindingNotFound) {
		t.Fatal("unbound OIDC identity resolved")
	}
	for _, table := range []string{"platform_identity_tenant", "platform_identity_department", "platform_identity_application", "platform_identity_principal", "platform_identity_oidc_binding", "platform_audit_event", "platform_notification_outbox"} {
		var count int
		if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT COUNT(*) FROM "+table)).Scan(&count); err != nil || count != 1 {
			t.Fatalf("wrong atomic bootstrap row count in %s", table)
		}
	}
	var summary, payload string
	if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT summary FROM platform_audit_event WHERE event_id='identity-first-admin-bootstrap'")).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT payload_json FROM platform_notification_outbox")).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{config.DBDSN, runtimeDSN.Password, config.Issuer, config.Subject} {
		if strings.Contains(summary+payload, secret) {
			t.Fatal("audit/outbox leaked bootstrap credentials or raw OIDC identity")
		}
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("UPDATE platform_identity_role_binding SET status='revoked',payload=jsonb_set(payload::jsonb,'{status}','\"revoked\"')::json WHERE subject_id=?"), resolved.Username); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("repeated initialization accepted")
	}
	current, err := store.ResolveOIDC(ctx, config.Issuer, config.Subject)
	if err != nil || len(current.Roles) != 0 {
		t.Fatal("repeated initialization restored revoked roles")
	}
	snapshot, err = store.PermissionSnapshot(ctx, identity.PrincipalUser, resolved.Username)
	if err != nil || snapshot.Bindings[0].Status != "revoked" {
		t.Fatal("reinitialization restored revoked super binding", err)
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("UPDATE platform_identity_oidc_binding SET status='disabled'")); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("disabled binding recreated")
	}
	if _, err := store.ResolveOIDC(ctx, config.Issuer, config.Subject); !errors.Is(err, identity.ErrOIDCBindingNotFound) {
		t.Fatal("disabled OIDC binding resolved")
	}
	if _, err := owner.ExecContext(ctx, sqlutil.Bind("UPDATE platform_identity_principal SET active=FALSE WHERE id=?"), resolved.Username); err != nil {
		t.Fatal(err)
	}
	if err := invoke(config); err == nil {
		t.Fatal("disabled principal restored")
	}
	var active bool
	if err := owner.QueryRowContext(ctx, sqlutil.Bind("SELECT active FROM platform_identity_principal WHERE id=?"), resolved.Username).Scan(&active); err != nil || active {
		t.Fatal("disabled principal changed")
	}
	digest := sha256.Sum256([]byte("first-admin:" + parsed.Database))
	lock := int64(binary.BigEndian.Uint64(digest[:8]))
	connection, err := owner.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var acquired bool
	if err := connection.QueryRowContext(ctx, sqlutil.Bind(`SELECT pg_try_advisory_lock(?)`), lock).Scan(&acquired); err != nil || !acquired {
		t.Fatal("bootstrap leaked PostgreSQL advisory lock")
	}
	var released bool
	if err := connection.QueryRowContext(ctx, sqlutil.Bind(`SELECT pg_advisory_unlock(?)`), lock).Scan(&released); err != nil || !released {
		t.Fatal("fixture unlock failed")
	}
}
