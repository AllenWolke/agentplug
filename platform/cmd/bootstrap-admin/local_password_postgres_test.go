package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestFirstAdministratorLocalPasswordPostgres(t *testing.T) {
	migration, runtime := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN"), os.Getenv("PUBLIC_TEST_POSTGRES_RUNTIME_DSN")
	if migration == "" || runtime == "" {
		t.Skip("requires owned PostgreSQL migration and DML fixture")
	}
	parsed, err := url.Parse(migration)
	if err != nil || parsed.Hostname() != "127.0.0.1" || parsed.Path != "/knowledge_test" {
		t.Fatal("owned fixture required")
	}
	ctx := context.Background()
	admin, err := sqlutil.OpenPostgres(ctx, migration)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, `REVOKE INSERT,UPDATE,DELETE ON platform_schema_version FROM knowledge_test_runtime; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public,knowledge TO knowledge_test_runtime`); err != nil {
		t.Fatal(err)
	}
	restrictBootstrapRuntimeFixture(t, ctx, admin, "knowledge_test_runtime")
	db, err := sqlutil.OpenPostgres(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	verifyBootstrapRuntimeFixture(t, ctx, db)
	config := fixtureConfiguration(t)
	config.DBDSN = runtime
	config.Issuer, config.Subject = "", ""
	config.PrincipalID = "system.admin"
	config.LocalPassword = "fixture-real-local-password-0123456789"
	fixtureCreated := false
	defer func() {
		if !fixtureCreated {
			return
		}
		// This test shares the owned integration database with the empty-store
		// bootstrap test. Remove only the exact rows created by this successful
		// invocation so later tests still exercise a genuinely empty store.
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM platform_notification_outbox WHERE event_id='identity-first-admin-bootstrap'`, nil},
			{`DELETE FROM platform_audit_event WHERE event_id='identity-first-admin-bootstrap'`, nil},
			{`DELETE FROM platform_identity_role_binding WHERE subject_id=? AND payload->>'source_id'=?`, []any{config.PrincipalID, "bootstrap:" + config.ApprovalReference}},
			{`DELETE FROM platform_identity_membership WHERE subject_id=? AND tenant_id=? AND department_id=? AND application_id=?`, []any{config.PrincipalID, config.TenantID, config.DepartmentID, config.ApplicationID}},
			{`DELETE FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`, []any{config.PrincipalID}},
			{`DELETE FROM platform_identity_local_credential WHERE principal_id=? AND tenant_id=? AND department_id=? AND application_id=?`, []any{config.PrincipalID, config.TenantID, config.DepartmentID, config.ApplicationID}},
			{`DELETE FROM platform_identity_principal WHERE id=? AND tenant_id=?`, []any{config.PrincipalID, config.TenantID}},
			{`DELETE FROM platform_identity_application WHERE id=? AND tenant_id=? AND department_id=?`, []any{config.ApplicationID, config.TenantID, config.DepartmentID}},
			{`DELETE FROM platform_identity_department WHERE id=? AND tenant_id=?`, []any{config.DepartmentID, config.TenantID}},
			{`DELETE FROM platform_identity_tenant WHERE id=?`, []any{config.TenantID}},
		} {
			if _, err := admin.ExecContext(context.Background(), sqlutil.Bind(statement.query), statement.args...); err != nil {
				t.Errorf("remove local administrator fixture rows: %v", err)
			}
		}
	}()
	raw, _ := json.Marshal(config)
	path := writeConfig(t, raw)
	invoke := func() error {
		var output bytes.Buffer
		err := run(ctx, []string{"--config", path}, &output)
		if strings.Contains(output.String(), config.LocalPassword) {
			t.Fatal("CLI leaked password")
		}
		return err
	}
	if _, err := admin.ExecContext(ctx, `CREATE FUNCTION fail_local_admin_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic outbox failure'; END $$; CREATE TRIGGER fail_local_admin_outbox BEFORE INSERT ON platform_notification_outbox FOR EACH ROW EXECUTE FUNCTION fail_local_admin_outbox()`); err != nil {
		t.Fatal(err)
	}
	if invoke() == nil {
		t.Fatal("outbox failure accepted")
	}
	for _, table := range []string{"platform_identity_principal", "platform_identity_local_credential", "platform_identity_role_binding", "platform_audit_event"} {
		var count int
		if err := admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("local bootstrap fault left rows", table, count, err)
		}
	}
	if _, err := admin.ExecContext(ctx, `DROP TRIGGER fail_local_admin_outbox ON platform_notification_outbox; DROP FUNCTION fail_local_admin_outbox()`); err != nil {
		t.Fatal(err)
	}
	if err := invoke(); err != nil {
		t.Fatal("actual local first administrator CLI failed", err)
	}
	fixtureCreated = true
	store := identity.NewSQLStore(db)
	authenticated, err := store.VerifyEnrollmentCredentials(ctx, config.PrincipalID, config.LocalPassword)
	if err != nil || authenticated.Username != config.PrincipalID || authenticated.TenantID != config.TenantID {
		t.Fatal("actual password authentication failed", err)
	}
	if _, err := store.VerifyEnrollmentCredentials(ctx, config.PrincipalID, "wrong-password-1234567890"); err == nil {
		t.Fatal("wrong password accepted")
	}
	snapshot, err := store.PermissionSnapshot(ctx, identity.PrincipalUser, config.PrincipalID)
	if err != nil || snapshot.Mode != "v2" || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].RoleCode != "super_admin" || len(snapshot.Grants) != 0 {
		t.Fatal("local super administrator received unexpected authority", err)
	}
	var oidc int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_identity_oidc_binding`).Scan(&oidc); err != nil || oidc != 0 {
		t.Fatal("local bootstrap fabricated OIDC binding", err, oidc)
	}
	var summary, payload, hash string
	if err := db.QueryRowContext(ctx, `SELECT summary FROM platform_audit_event WHERE event_id='identity-first-admin-bootstrap'`).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT payload_json FROM platform_notification_outbox`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT password_hash FROM platform_identity_local_credential WHERE principal_id='system.admin'`).Scan(&hash); err != nil || hash == config.LocalPassword || strings.Contains(summary+payload, config.LocalPassword) {
		t.Fatal("stored plaintext or audit secret leak", err)
	}
	if invoke() == nil {
		t.Fatal("existing identity allowed rebootstrap")
	}
	if _, err := admin.ExecContext(ctx, `UPDATE platform_identity_local_credential SET active=FALSE WHERE principal_id='system.admin'`); err != nil {
		t.Fatal(err)
	}
	if invoke() == nil {
		t.Fatal("rebootstrap restored disabled credential")
	}
	if _, err := store.VerifyEnrollmentCredentials(ctx, config.PrincipalID, config.LocalPassword); err == nil {
		t.Fatal("disabled local credential authenticated")
	}
}
