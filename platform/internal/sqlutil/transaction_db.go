package sqlutil

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
)

// TransactionDB lends one existing transaction to schema repositories that use
// database/sql pools. It cannot open a second connection, begin nested work or
// commit the owner's transaction. Closing the facade never closes the owner.
func TransactionDB(tx *sql.Tx) *sql.DB {
	db := sql.OpenDB(transactionConnector{tx: tx})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db
}

type transactionConnector struct{ tx *sql.Tx }

func (c transactionConnector) Connect(context.Context) (driver.Conn, error) {
	return transactionConnection{c.tx}, nil
}
func (transactionConnector) Driver() driver.Driver { return transactionDriver{} }

type transactionDriver struct{}

func (transactionDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("transaction connector required")
}

type transactionConnection struct{ tx *sql.Tx }

func (transactionConnection) Close() error { return nil }
func (transactionConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("nested migration transactions are forbidden")
}
func (transactionConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("migration statements must execute with context")
}
func namedArguments(values []driver.NamedValue) []any {
	args := make([]any, len(values))
	for i, value := range values {
		args[i] = value.Value
	}
	return args
}
func (c transactionConnection) ExecContext(ctx context.Context, query string, values []driver.NamedValue) (driver.Result, error) {
	return c.tx.ExecContext(ctx, query, namedArguments(values)...)
}
func (c transactionConnection) QueryContext(ctx context.Context, query string, values []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.tx.QueryContext(ctx, query, namedArguments(values)...)
	if err != nil {
		return nil, err
	}
	columns, err := rows.Columns()
	if err != nil {
		_ = rows.Close()
		return nil, err
	}
	return &transactionRows{rows: rows, columns: columns}, nil
}

type transactionRows struct {
	rows    *sql.Rows
	columns []string
}

func (r *transactionRows) Columns() []string { return r.columns }
func (r *transactionRows) Close() error      { return r.rows.Close() }
func (r *transactionRows) Next(dest []driver.Value) error {
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	values := make([]any, len(dest))
	args := make([]any, len(dest))
	for i := range values {
		args[i] = &values[i]
	}
	if err := r.rows.Scan(args...); err != nil {
		return err
	}
	for i, value := range values {
		dest[i] = value
	}
	return nil
}
