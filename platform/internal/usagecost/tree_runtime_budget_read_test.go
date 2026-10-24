package usagecost

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lexagent/platform/internal/sharedkernel"
)

type budgetReadAuthorityFixture struct {
	*treeBudgetSQLTestAuthority
	reads, writes int
	readError     error
}

func (a *budgetReadAuthorityFixture) ReadFacts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) (RunTreeBudgetFacts, error) {
	a.reads++
	if a.readError != nil {
		return RunTreeBudgetFacts{}, a.readError
	}
	return a.treeBudgetSQLTestAuthority.Facts(ctx, tx, scope, true)
}
func (a *budgetReadAuthorityFixture) Facts(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, admission bool) (RunTreeBudgetFacts, error) {
	a.writes++
	return a.treeBudgetSQLTestAuthority.Facts(ctx, tx, scope, admission)
}

func TestSQLRuntimeBudgetReadAuthorityCannotReplaceWriteAdmission(t *testing.T) {
	tree, window, base, _, ctx := newTreeBudgetSQLTestFixture(t)
	root := newTreeBudgetTestRoot(t)
	base.AddScope(root, root, treeBudgetTestPolicyHash(root), 100, 100)
	authority := &budgetReadAuthorityFixture{treeBudgetSQLTestAuthority: base}
	tree.SetAuthority(authority)
	command := treeBudgetTestCommand("reserve", "read-fixture", fingerprintFor(root.RunID), RunTreeBudgetHold{Micros: 25, Tokens: 30})
	if _, err := tree.Apply(ctx, root, command); err != nil {
		t.Fatal(err)
	}
	if authority.reads != 0 || authority.writes != 2 {
		t.Fatal("read facts replaced write checks", authority.reads, authority.writes)
	}
	read := func() (RunTreeBudgetReceipt, error) {
		tx, err := window.db.BeginTx(ctx, nil)
		if err != nil {
			return RunTreeBudgetReceipt{}, err
		}
		defer tx.Rollback()
		receipt, err := tree.ReadRuntimeBudgetTx(ctx, tx, root)
		if err != nil {
			return receipt, err
		}
		return receipt, tx.Commit()
	}
	receipt, err := read()
	if err != nil || receipt.Counters.HeldMicros != 25 || receipt.Counters.HeldTokens != 30 || authority.reads != 1 || authority.writes != 2 {
		t.Fatalf("read lost original hold or entered write admission: %+v %v reads=%d writes=%d", receipt, err, authority.reads, authority.writes)
	}
	authority.readError = ErrBudgetScopeMismatch
	if _, err := read(); !errors.Is(err, ErrBudgetScopeMismatch) {
		t.Fatal("denied read fell back to old authority", err)
	}
	if authority.writes != 2 {
		t.Fatal("failed read used a weaker fallback")
	}
	tree.SetAuthority(base)
	if receipt, err = read(); err != nil || receipt.Counters.HeldMicros != 25 {
		t.Fatal("legacy authority read contract changed", err)
	}
}
