package knowledge

import (
	"context"
	"database/sql"
	"errors"
)

// CheckRevisionTx fences the captured source revision in a caller-owned
// transaction without loading document bodies. Composition acquires IAM and
// task lease fences before this collection lock. Missing collections are
// revision zero; final publication creates and locks their durable head.
func (p PostgresSource) CheckRevisionTx(ctx context.Context, tx *sql.Tx, scope ProjectionScope, expected int64) error {
	if p.DB == nil || tx == nil || !scope.valid() || expected < 0 {
		return ErrInvalidProjection
	}
	var revision int64
	err := tx.QueryRowContext(ctx, `SELECT source_revision FROM platform_knowledge_source_head WHERE tenant_id=$1 AND department_id=$2 AND application_id=$3 AND knowledge_id=$4 FOR SHARE`, scope.args()...).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if revision != expected {
		return ErrSourceConflict
	}
	return nil
}
