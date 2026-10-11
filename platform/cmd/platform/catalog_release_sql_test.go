package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/catalog"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sqlutil"
	"net/url"
)

type releaseAuditFault struct {
	recorder audit.TxRecorder
	fail     bool
}

func (f *releaseAuditFault) RecordTx(tx *sql.Tx, event audit.Event) error {
	if err := f.recorder.RecordTx(tx, event); err != nil {
		return err
	}
	if f.fail {
		return errors.New("injected failure after actual audit and outbox inserts")
	}
	return nil
}

func TestSQLCatalogReleaseActualIAMAndAuditOutbox(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL fixture required")
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
	name := fmt.Sprintf("catalog_release_fixture_%d", time.Now().UnixNano())
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
	iam := identity.NewSQLStore(db)
	outbox := notification.NewSQLStore(db)
	auditStore := audit.NewSQLStoreWithOutbox(db, outbox)
	store := catalog.NewSQLStore(db, "pgx")
	for _, ensure := range []func(context.Context) error{iam.EnsureSchema, outbox.EnsureSchema, auditStore.EnsureSchema, store.EnsureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	fault := &releaseAuditFault{recorder: auditStore}
	configureCatalogRelease(store, iam, fault)
	for _, err := range []error{
		iam.CreateTenant(ctx, identity.Tenant{ID: "t", Code: "t", Name: "fixture", Status: "active", Revision: 1}),
		iam.CreateDepartment(ctx, identity.Department{ID: "d", TenantID: "t", Code: "d", Name: "fixture", Status: "active", Revision: 1}),
		iam.CreateApplication(ctx, identity.Application{ID: "a", TenantID: "t", DepartmentID: "d", Code: "a", Name: "fixture", Status: "active", Revision: 1}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Fixture facts are inserted directly; all release decisions use actual SQL IAM.
	// No login, credential migration or administrator continuity claim is made here.
	setBinding := func(user, status string) {
		t.Helper()
		b := identity.RoleBinding{ID: user + "-binding", SubjectID: user, RoleCode: "super_admin", RoleVersion: 1, Scope: identity.ManagementScope{Type: "global"}, Status: status, Revision: 1, SourceID: "isolated-fixture"}
		payload, _ := json.Marshal(b)
		source, _ := json.Marshal([]any{b.SubjectID, b.RoleCode, b.RoleVersion, b.Scope, b.SourceID})
		hash := fmt.Sprintf("%x", sha256.Sum256(source))
		_, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_role_binding(id,subject_id,role_code,role_version,tenant_id,department_id,application_id,status,revision,payload,source_hash) VALUES(?,?,?,1,'','','',?,1,?,?) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,payload=EXCLUDED.payload,revision=platform_identity_role_binding.revision+1`), b.ID, user, b.RoleCode, status, string(payload), hash)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []string{"alice", "bob"} {
		if err := iam.CreatePrincipal(ctx, identity.Principal{Type: identity.PrincipalUser, ID: user, TenantID: "t", IsActive: true, Roles: []string{"admin"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'v2',1,1)`), user); err != nil {
			t.Fatal(err)
		}
		setBinding(user, "active")
	}
	alice := catalog.ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice", TraceID: "submission-trace"}
	bob := alice
	bob.PrincipalID = "bob"
	bob.TraceID = "approval-trace"
	checkEvents := func(t *testing.T, id, action, actor string, want int) {
		t.Helper()
		var auditCount, outboxCount int
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_audit_event WHERE aggregate_id=? AND action=? AND actor_id=? AND tenant_id='t' AND department_id='d' AND application_id='a'`), id, "catalog.release."+action, actor).Scan(&auditCount); err != nil {
			t.Fatal(err)
		}
		kind := "definition"
		if id == "release-version" {
			kind = "version"
		}
		eventID := fmt.Sprintf("audit-catalog-release-%x", sha256.Sum256([]byte(kind+":"+id+":"+action)))
		if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_notification_outbox WHERE event_id=?`), eventID).Scan(&outboxCount); err != nil {
			t.Fatal(err)
		}
		if auditCount != want || outboxCount != want {
			t.Fatalf("%s %s audit=%d outbox=%d wanted=%d", id, action, auditCount, outboxCount, want)
		}
	}
	definition := catalog.Definition{ID: "release-definition", PublisherID: "publisher", AgentKey: "example", DisplayName: "Example", Description: "fixture", Status: catalog.DefinitionDraft, Revision: 1}
	manifest := json.RawMessage(`{"manifest_version":"agent-manifest/v1","agent_id":"example","version":"1.0.0","execution_protocols":["agent-execution/v2"],"capabilities":["invoke"],"schemas":{"input":"schema://example/input/v1","output":"schema://example/output/v1","event":"schema://example/event/v1","checkpoint":"schema://example/checkpoint/v1"},"runtime":{"transport":"http","isolation":"container","health_path":"/health/ready"}}`)
	schema := json.RawMessage(`{"type":"object"}`)
	hash, err := catalog.VersionContentHash(manifest, schema, schema)
	if err != nil {
		t.Fatal(err)
	}
	version := catalog.Version{ID: "release-version", DefinitionID: definition.ID, SemanticVersion: "1.0.0", ManifestHash: hash, Manifest: manifest, ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", InputSchema: schema, OutputSchema: schema, Status: catalog.DefinitionDraft, Revision: 1}
	for _, kind := range []string{"definition", "version"} {
		t.Run(kind, func(t *testing.T) {
			id := definition.ID
			if kind == "version" {
				id = version.ID
			}
			create := func() error {
				if kind == "definition" {
					return store.CreateSubmittedDefinition(ctx, definition, alice)
				}
				return store.CreateSubmittedVersion(ctx, version, alice)
			}
			fault.fail = true
			if err := create(); err == nil {
				t.Fatal("submission ignored actual audit/outbox fault")
			}
			checkEvents(t, id, "submitted", "alice", 0)
			fault.fail = false
			if err := create(); err != nil {
				t.Fatal(err)
			}
			checkEvents(t, id, "submitted", "alice", 1)
			if kind == "definition" {
				err = store.TransitionDefinition(ctx, id, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1)
			} else {
				err = store.TransitionVersion(ctx, id, catalog.DefinitionDraft, catalog.DefinitionEvaluated, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, alice); !errors.Is(err, catalog.ErrCatalogForbidden) {
				t.Fatal("actual IAM permitted self approval", err)
			}
			setBinding("bob", "revoked")
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, bob); !errors.Is(err, catalog.ErrCatalogForbidden) {
				t.Fatal("revoked v2 binding fell back to admin", err)
			}
			setBinding("bob", "active")
			fault.fail = true
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, bob); err == nil {
				t.Fatal("approval ignored actual audit/outbox fault")
			}
			checkEvents(t, id, "approved", "bob", 0)
			var approved string
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT approved_by FROM platform_catalog_submission WHERE object_kind=? AND object_id=?`), kind, id).Scan(&approved); err != nil || approved != "" {
				t.Fatal("approval provenance did not roll back", err)
			}
			fault.fail = false
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, bob); err != nil {
				t.Fatal(err)
			}
			bob.TraceID = "retry-trace"
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, bob); err != nil {
				t.Fatal("retry", err)
			}
			checkEvents(t, id, "approved", "bob", 1)
			setBinding("bob", "revoked")
			if err := store.PublishSubmittedObject(ctx, kind, id, 2, bob); !errors.Is(err, catalog.ErrCatalogForbidden) {
				t.Fatal("revoked replay", err)
			}
			setBinding("bob", "active")
		})
	}
}
