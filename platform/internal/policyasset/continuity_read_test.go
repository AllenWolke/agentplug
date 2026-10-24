package policyasset

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPolicyAuthorityReadJoinsOwnerConnection(t *testing.T) {
	dsn := os.Getenv("PUBLIC_TEST_POSTGRES_MIGRATION_DSN")
	if dsn == "" {
		t.Skip("owned PostgreSQL migration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, e := sqlutil.OpenPostgres(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	r := NewSQLResolver(db)
	if e := r.EnsureSchema(ctx); e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	owner, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Rollback()
	scope := sharedkernel.Scope{TenantID: "continuity-absent", DepartmentID: "d", ApplicationID: "a", AgentID: "agent", PrincipalType: "user", PrincipalID: "user"}
	read := func(c context.Context) error { _, e := r.Resolve(c, scope, "v1"); return e }
	bounded, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	waits := db.Stats().WaitCount
	if e := read(sqlutil.WithContinuityTransaction(bounded, db, owner)); !errors.Is(e, ErrPolicyNotFound) || db.Stats().WaitCount != waits {
		t.Fatalf("nested policy read: wait_delta=%d err=%v", db.Stats().WaitCount-waits, e)
	}
	if e := read(sqlutil.WithContinuityTransaction(ctx, new(sql.DB), owner)); e == nil || errors.Is(e, ErrPolicyNotFound) {
		t.Fatal("foreign owner ignored", e)
	}
	if e := owner.Rollback(); e != nil {
		t.Fatal(e)
	}
	if e := read(sqlutil.WithContinuityTransaction(ctx, db, owner)); !errors.Is(e, sql.ErrTxDone) {
		t.Fatal("closed owner ignored", e)
	}
}
