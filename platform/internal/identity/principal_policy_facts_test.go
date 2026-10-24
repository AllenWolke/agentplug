package identity

import (
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sqlutil"
)

func TestSQLPrincipalPolicyFactsAreFreshAndNotPermissionDecisions(t *testing.T) {
	f := newAdministratorFixture(t)
	id := f.actors[2].PrincipalID
	before, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, id)
	if err != nil || before.ID != id || before.Type != PrincipalUser || before.TenantID != f.actors[2].TenantID || !before.IsActive || before.Mode != "v2" {
		t.Fatalf("authentication facts: %+v %v", before, err)
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AcquirePermissionReadContinuity(f.ctx, tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	inTransaction, err := f.store.PrincipalPolicyFactsTx(f.ctx, tx, PrincipalUser, id)
	if err != nil || inTransaction != before {
		tx.Rollback()
		t.Fatal("transaction facts changed", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`UPDATE platform_identity_principal SET active=FALSE,revision=revision+1 WHERE principal_type='user' AND id=?`), id); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, id)
	if err != nil || after.IsActive || after.Revision <= before.Revision {
		t.Fatalf("stale principal: %+v %v", after, err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`DELETE FROM platform_identity_policy_migration WHERE principal_type='user' AND subject_id=?`), id); err != nil {
		t.Fatal(err)
	}
	after, err = f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, id)
	if err != nil || after.Mode != "legacy" {
		t.Fatal("stale migration mode", after.Mode, err)
	}
	if _, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, "absent"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatal("missing principal", err)
	}
	if _, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalType("untrusted"), id); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatal("invalid principal type", err)
	}
	if _, err := f.db.ExecContext(f.ctx, sqlutil.Bind(`INSERT INTO platform_identity_policy_migration(principal_type,subject_id,policy_mode,revision,epoch) VALUES('user',?,'corrupt',1,1)`), id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.PrincipalPolicyFacts(f.ctx, PrincipalUser, id); !errors.Is(err, ErrInvalidResource) {
		t.Fatal("invalid migration mode", err)
	}
}
