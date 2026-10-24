package sqlutil

import (
	"context"
	"database/sql"
	"errors"
)

type continuityTransactionKey struct{}
type continuityTransaction struct {
	db *sql.DB
	tx *sql.Tx
}

// WithContinuityTransaction joins immediate authorization reads to the owner
// of a protected local transaction. It conveys no permission and must never be
// installed from request data. The owner retains commit/rollback responsibility;
// a consumer must keep checking current facts, time and its own resource scope.
// In particular, a joined IAM check must not advance a durable authorization
// epoch inside a business transaction that can later roll back.
func WithContinuityTransaction(ctx context.Context, db *sql.DB, tx *sql.Tx) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, continuityTransactionKey{}, continuityTransaction{db: db, tx: tx})
}

// ContinuityTransaction distinguishes absence from an invalid/foreign binding.
// Consumers must not open another transaction after a binding error. A closed
// transaction remains bound and fails through database/sql, never by fallback.
func ContinuityTransaction(ctx context.Context, db *sql.DB) (*sql.Tx, bool, error) {
	if ctx == nil {
		return nil, false, nil
	}
	bound, ok := ctx.Value(continuityTransactionKey{}).(continuityTransaction)
	if !ok {
		return nil, false, nil
	}
	if db == nil || bound.db != db || bound.tx == nil {
		return nil, true, errors.New("invalid continuity transaction binding")
	}
	return bound.tx, true, nil
}

// ContinuityQueryer borrows only the query surface of an owner's transaction.
// It conveys no authorization and cannot complete or mutate that transaction.
type ContinuityQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ContinuityReader keeps immediate reads on the connection already owned by
// a protected local operation. Holding one pool connection while requesting
// another can starve every owner under load. An invalid binding must not escape
// through a new connection; a closed transaction returns sql.ErrTxDone through
// its query methods. Every consumer still reads and validates current facts.
func ContinuityReader(ctx context.Context, db *sql.DB) (ContinuityQueryer, error) {
	if db == nil {
		return nil, errors.New("continuity database reader unavailable")
	}
	if tx, joined, err := ContinuityTransaction(ctx, db); joined {
		if err != nil {
			return nil, err
		}
		return tx, nil
	}
	return db, nil
}
