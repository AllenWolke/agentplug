package identity

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPrincipalPolicyFactsJoinsOwnerConnection(t *testing.T) {
	f := newAdministratorFixture(t)
	id := f.actors[2].PrincipalID
	f.db.SetMaxOpenConns(1)
	owner, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Rollback()
	if err := f.store.AcquirePermissionReadContinuity(f.ctx, owner); err != nil {
		t.Fatal(err)
	}
	// An uncommitted owner-side change also proves which connection supplied
	// the facts. This test never changes a live service's IAM data.
	if _, err := owner.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE,revision=revision+1 WHERE principal_type='user' AND id=?`), id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	defer cancel()
	bound := sqlutil.WithContinuityTransaction(ctx, f.db, owner)
	waits := f.db.Stats().WaitCount
	facts, err := f.store.PrincipalPolicyFacts(bound, PrincipalUser, id)
	if err != nil || facts.ID != id || facts.IsActive || f.db.Stats().WaitCount != waits {
		t.Fatalf("owner read opened another connection or missed current facts: active=%v wait_delta=%d err=%v", facts.IsActive, f.db.Stats().WaitCount-waits, err)
	}
	foreign := sqlutil.WithContinuityTransaction(f.ctx, new(sql.DB), owner)
	if _, err := f.store.PrincipalPolicyFacts(foreign, PrincipalUser, id); err == nil {
		t.Fatal("foreign owner escaped into pool")
	}
	if err := owner.Rollback(); err != nil {
		t.Fatal(err)
	}
	closed := sqlutil.WithContinuityTransaction(f.ctx, f.db, owner)
	if _, err := f.store.PrincipalPolicyFacts(closed, PrincipalUser, id); !errors.Is(err, sql.ErrTxDone) {
		t.Fatal("closed owner escaped into pool", err)
	}
	current, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, id)
	if err != nil || !current.IsActive {
		t.Fatal("owner was committed or standalone read changed", err)
	}
}
