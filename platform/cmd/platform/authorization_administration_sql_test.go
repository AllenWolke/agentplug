package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

func TestSQLAuthorizationAdministrationVersionAndLifecycleAtomic(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}

	uri, err := url.Parse(dsn)
	if err != nil || uri.Hostname() != "127.0.0.1" || uri.Path != "/knowledge_test" || (uri.Scheme != "postgres" && uri.Scheme != "postgresql") {
		t.Fatal("dedicated loopback PostgreSQL fixture required")
	}
	control, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	name := fmt.Sprintf("authorization_fixture_%d", time.Now().UnixNano())
	if _, err = control.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := control.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Error(err)
		}
	}()
	uri.Path = "/" + name
	dsn = uri.String()
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	iam, outbox := identity.NewSQLStore(db), notification.NewSQLStore(db)
	auditor := audit.NewSQLStoreWithOutbox(db, outbox)
	for _, ensure := range []func(context.Context) error{iam.EnsureSchema, outbox.EnsureSchema, auditor.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []identity.PrincipalType{identity.PrincipalUser, identity.PrincipalServicePrincipal} {
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_principal(id,principal_type,tenant_id,roles_json,groups_json,active,revision,created_at) VALUES('subject',?,'tenant','[]','[]',TRUE,100,NOW())`), kind); err != nil {
			t.Fatal(err)
		}
	}
	scope := sharedkernel.Scope{TenantID: "tenant", DepartmentID: "department", ApplicationID: "application", PrincipalType: "user", PrincipalID: "actor", TraceID: "fixture-trace"}
	recorder := recordVersionedAdministration(auditor, outbox, iam)
	types := []identity.PrincipalType{identity.PrincipalUser, identity.PrincipalUser, identity.PrincipalServicePrincipal, identity.PrincipalServicePrincipal, identity.PrincipalServicePrincipal}
	actions := []string{"administrator.appoint", "delegation.manage", "machine.manage", "machine.manage", "machine.manage"}
	for i, kind := range types {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type=? AND id='subject'`), kind); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		event := identity.AdministrativeEvent{ID: fmt.Sprintf("administration-%d", i), SubjectType: kind, ActorID: "actor", SubjectID: "subject", Action: actions[i], Revision: 2, OccurredAt: time.Now().UTC()}
		if err := recorder(ctx, tx, scope, event); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var raw string
		if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT payload_json FROM platform_notification_outbox WHERE event_id=?`), "authorization-"+event.ID).Scan(&raw); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		expected := uint64(101 + i)
		if kind == identity.PrincipalServicePrincipal {
			expected = uint64(99 + i)
		}
		if payload["aggregate_revision"] != fmt.Sprint(expected) || payload["subject_type"] != string(kind) {
			tx.Rollback()
			t.Fatal("transaction principal revision/type lost", payload)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	// A version-event write that fails after actual insertion must roll back all facts.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET revision=revision+1 WHERE principal_type='service_principal' AND id='subject'`)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	faultRecorder := recordVersionedAdministration(auditor, authorizationOutboxFault{outbox}, iam)
	if err := faultRecorder(ctx, tx, scope, identity.AdministrativeEvent{ID: "failed-machine-change", SubjectType: identity.PrincipalServicePrincipal, ActorID: "actor", SubjectID: "subject", Action: "machine.manage", Revision: 2, OccurredAt: time.Now().UTC()}); err == nil {
		tx.Rollback()
		t.Fatal("outbox failure ignored")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	p, err := iam.GetPrincipal(ctx, identity.PrincipalServicePrincipal, "subject")
	if err != nil || p.Revision != 103 {
		t.Fatal("failed event changed principal version", err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iam.AuthorizationVersionTx(ctx, tx, "other-tenant", identity.PrincipalUser, "subject"); err == nil {
		tx.Rollback()
		t.Fatal("cross-tenant version returned")
	}
	tx.Rollback()
	iam.SetPrincipalLifecycleRecorder(recordVersionedPrincipalLifecycle(auditor, outbox))
	principal, err := iam.DisablePrincipal(ctx, scope, "subject", 102)
	if err != nil || principal.IsActive || principal.Revision != 103 {
		t.Fatal("actual principal lifecycle failed", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE event_type=?`), notification.AuthorizationChangedV1).Scan(&count); err != nil || count != 6 {
		t.Fatal("version event count/rollback mismatch", count, err)
	}
	if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event`)).Scan(&count); err != nil || count != 6 {
		t.Fatal("audit rollback mismatch", count, err)
	}
	t.Log("Five typed administrative events read uncommitted principal versions; same ID across user/machine remained distinct; outbox fault rolled back; actual principal disable emitted revision 103.")
}
