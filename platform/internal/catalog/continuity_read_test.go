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

func TestSQLCatalogAuthorityReadsJoinOwnerConnection(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL migration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	db, err := sqlutil.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewSQLStore(db, "pgx")
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	checks := []struct {
		name   string
		absent error
		read   func(context.Context) error
	}{
		{"definition", ErrDefinitionNotFound, func(c context.Context) error { _, e := s.GetDefinition(c, "continuity-absent"); return e }},
		{"version", ErrVersionNotFound, func(c context.Context) error { _, e := s.GetVersion(c, "continuity-absent"); return e }},
		{"installation", ErrInstallationNotFound, func(c context.Context) error { _, e := s.GetInstallation(c, "continuity-absent"); return e }},
		{"installations", nil, func(c context.Context) error {
			_, e := s.ListInstallations(c, "continuity-absent", "d", "a", 1)
			return e
		}},
		{"deployments", nil, func(c context.Context) error {
			_, e := s.ListDeployments(c, "continuity-absent", "d", "a", "i", 1)
			return e
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			owner, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer owner.Rollback()
			bounded, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			bound := sqlutil.WithContinuityTransaction(bounded, db, owner)
			waits := db.Stats().WaitCount
			if e := check.read(bound); !errors.Is(e, check.absent) || db.Stats().WaitCount != waits {
				t.Fatalf("nested catalog read: wait_delta=%d err=%v", db.Stats().WaitCount-waits, e)
			}
			foreign := sqlutil.WithContinuityTransaction(ctx, new(sql.DB), owner)
			if e := check.read(foreign); e == nil || errors.Is(e, check.absent) {
				t.Fatal("foreign owner ignored", e)
			}
			if e := owner.Rollback(); e != nil {
				t.Fatal(e)
			}
			closed := sqlutil.WithContinuityTransaction(ctx, db, owner)
			if e := check.read(closed); !errors.Is(e, sql.ErrTxDone) {
				t.Fatal("closed owner ignored", e)
			}
		})
	}
}
