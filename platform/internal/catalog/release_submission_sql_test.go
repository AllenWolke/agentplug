package catalog

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLCatalogReleaseAtomicityProvenanceAndRetry(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL migration fixture required")
	}
	db, err := sqlutil.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := NewSQLStore(db, "pgx")
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	// This local receipt is a fault-injection port, not a claim of Root IAM/Audit acceptance.
	if _, err := db.ExecContext(ctx, sqlutil.Bind(`CREATE TABLE catalog_release_test_receipt (kind VARCHAR(32), object_id VARCHAR(128), action VARCHAR(32), actor VARCHAR(128), PRIMARY KEY(kind,object_id,action))`)); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), sqlutil.Bind(`DROP TABLE catalog_release_test_receipt`))
	authorized, failRecord, loseAfterRecord := true, false, false
	s.SetReleasePorts(func(context.Context, *sql.Tx) error { return nil }, func(_ context.Context, a ControlActor, action ControlAction) error {
		if !authorized || (action != ControlSubmit && action != ControlApprove) {
			return ErrCatalogForbidden
		}
		return nil
	}, func(ctx context.Context, tx *sql.Tx, d ReleaseDecision) error {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO catalog_release_test_receipt (kind,object_id,action,actor) VALUES (?,?,?,?)`), d.Kind, d.ID, d.Action, d.Actor.PrincipalID); err != nil {
			return err
		}
		if failRecord {
			return errors.New("injected receipt fault")
		}
		if loseAfterRecord {
			authorized = false
		}
		return nil
	})
	alice := ControlActor{TenantID: "t", DepartmentID: "d", ApplicationID: "a", PrincipalType: "user", PrincipalID: "alice"}
	bob := alice
	bob.PrincipalID = "bob"
	checkCount := func(table, id string, want int) {
		t.Helper()
		var got int
		var err error
		switch table {
		case "definition":
			err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_catalog_definition WHERE id=?`), id).Scan(&got)
		case "version":
			err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_catalog_version WHERE id=?`), id).Scan(&got)
		case "artifact":
			err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_catalog_version_artifact WHERE version_id=?`), id).Scan(&got)
		case "submission":
			err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM platform_catalog_submission WHERE object_id=?`), id).Scan(&got)
		case "approval":
			err = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT COUNT(*) FROM catalog_release_test_receipt WHERE object_id=? AND action='approved'`), id).Scan(&got)
		}
		if err != nil || got != want {
			t.Fatalf("%s %s count=%d wanted=%d: %v", table, id, got, want, err)
		}
	}
	for _, kind := range []string{"definition", "version"} {
		t.Run(kind, func(t *testing.T) {
			id := "release-" + kind
			d := definition()
			d.ID = id
			d.AgentKey = id
			d.Status = DefinitionDraft
			d.Revision = 1
			v := version()
			v.ID = id
			v.DefinitionID = "release-definition"
			v.Status = DefinitionDraft
			v.Revision = 1
			// The version manifest must identify its actual definition.
			if kind == "version" {
				parent, err := s.GetDefinition(ctx, v.DefinitionID)
				if err != nil {
					t.Fatal(err)
				}
				parent.AgentKey = "example-agent"
				if _, err := db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_catalog_definition SET agent_key=? WHERE id=?`), parent.AgentKey, parent.ID); err != nil {
					t.Fatal(err)
				}
			}
			create := func() error {
				if kind == "definition" {
					return s.CreateSubmittedDefinition(ctx, d, alice)
				}
				return s.CreateSubmittedVersion(ctx, v, alice)
			}
			failRecord = true
			if err := create(); err == nil {
				t.Fatal("submission ignored recorder fault")
			}
			checkCount(kind, id, 0)
			checkCount("submission", id, 0)
			if kind == "version" {
				checkCount("artifact", id, 0)
			}
			failRecord = false
			if err := create(); err != nil {
				t.Fatal(err)
			}
			if kind == "definition" {
				err = s.TransitionDefinition(ctx, id, DefinitionDraft, DefinitionEvaluated, 1)
			} else {
				err = s.TransitionVersion(ctx, id, DefinitionDraft, DefinitionEvaluated, 1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.PublishSubmittedObject(ctx, kind, id, 2, alice); !errors.Is(err, ErrCatalogForbidden) {
				t.Fatal("self approval", err)
			}
			failRecord = true
			if err := s.PublishSubmittedObject(ctx, kind, id, 2, bob); err == nil {
				t.Fatal("approval ignored recorder fault")
			}
			failRecord = false
			loseAfterRecord = true
			if err := s.PublishSubmittedObject(ctx, kind, id, 2, bob); !errors.Is(err, ErrCatalogForbidden) {
				t.Fatal("late authorization loss", err)
			}
			loseAfterRecord = false
			authorized = true
			checkCount("approval", id, 0)
			var approved string
			var revision uint64
			if err := db.QueryRowContext(ctx, sqlutil.Bind(`SELECT approved_by,approved_revision FROM platform_catalog_submission WHERE object_kind=? AND object_id=?`), kind, id).Scan(&approved, &revision); err != nil || approved != "" || revision != 0 {
				t.Fatal("rollback retained approval", err)
			}
			for retry := 0; retry < 2; retry++ {
				if err := s.PublishSubmittedObject(ctx, kind, id, 2, bob); err != nil {
					t.Fatal("publish/retry", err)
				}
			}
			checkCount("approval", id, 1)
			if kind == "definition" {
				row, e := s.GetDefinition(ctx, id)
				if e != nil || row.Revision != 3 || row.Status != DefinitionPublished || row.SubmittedBy != "alice" || row.ApprovedBy != "bob" {
					t.Fatal("definition projection", row, e)
				}
			} else {
				row, e := s.GetVersion(ctx, id)
				if e != nil || row.Revision != 3 || row.Status != DefinitionPublished || row.SubmittedBy != "alice" || row.ApprovedBy != "bob" {
					t.Fatal("version projection", row, e)
				}
			}
			authorized = false
			if err := s.PublishSubmittedObject(ctx, kind, id, 2, bob); !errors.Is(err, ErrCatalogForbidden) {
				t.Fatal("revoked replay accepted", err)
			}
			authorized = true
		})
	}
	legacy := definition()
	legacy.ID = "legacy-release"
	legacy.AgentKey = "legacy-release"
	legacy.Status = DefinitionDraft
	legacy.Revision = 1
	if err := s.CreateDefinition(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionDefinition(ctx, legacy.ID, DefinitionDraft, DefinitionEvaluated, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishSubmittedObject(ctx, "definition", legacy.ID, 2, bob); !errors.Is(err, ErrReleaseSubmissionMissing) {
		t.Fatal("historical creator invented", err)
	}
}
