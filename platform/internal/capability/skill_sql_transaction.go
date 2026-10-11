package capability

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sharedkernel"
)

// SkillSQLTransactionFence establishes IAM and execution ownership before a
// skill namespace lock is taken. The composition root supplies the production
// authority; skill storage does not construct another module's SQL authority.
type SkillSQLTransactionFence interface {
	AcquireTransactionFence(context.Context, *sql.Tx, sharedkernel.Scope) error
}

type skillSQLTransactionContextKey struct{}

type skillSQLTransactionBinding struct {
	db    *sql.DB
	tx    *sql.Tx
	scope sharedkernel.Scope
}

// WithSQLSkillTransaction binds a trusted caller-owned SQL transaction to the
// skill registry for one exact scope. It is a composition-only context port;
// no request or JSON field is consulted when selecting the transaction.
func WithSQLSkillTransaction(ctx context.Context, db *sql.DB, tx *sql.Tx, scope sharedkernel.Scope) context.Context {
	if ctx == nil || db == nil || tx == nil || scope.ValidateTrusted() != nil {
		return ctx
	}
	return context.WithValue(ctx, skillSQLTransactionContextKey{}, skillSQLTransactionBinding{db: db, tx: tx, scope: scope})
}

func skillSQLTransactionFromContext(ctx context.Context, db *sql.DB, scope sharedkernel.Scope) (*sql.Tx, bool, error) {
	if ctx == nil {
		return nil, false, nil
	}
	binding, ok := ctx.Value(skillSQLTransactionContextKey{}).(skillSQLTransactionBinding)
	if !ok {
		return nil, false, nil
	}
	if db == nil || binding.db != db || binding.tx == nil || binding.scope != scope || scope.ValidateTrusted() != nil {
		return nil, true, ErrSkillDenied
	}
	return binding.tx, true, nil
}
