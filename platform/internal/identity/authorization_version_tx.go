package identity

import (
	"context"
	"database/sql"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// AuthorizationVersionTx reads the principal version from the caller's change
// transaction, including uncommitted increments. Credential/binding revisions
// must never substitute for this aggregate version in invalidation events.
func (s *SQLStore) AuthorizationVersionTx(ctx context.Context, tx *sql.Tx, tenant string, kind PrincipalType, id string) (uint64, error) {
	if s == nil || s.db == nil || tx == nil || tenant == "" || id == "" || (kind != PrincipalUser && kind != PrincipalServicePrincipal) {
		return 0, ErrInvalidPrincipal
	}
	var revision uint64
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision FROM platform_identity_principal WHERE principal_type=? AND id=? AND tenant_id=? FOR UPDATE`), kind, id, tenant).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrPrincipalNotFound
	}
	if err != nil {
		return 0, err
	}
	if revision == 0 {
		return 0, ErrInvalidPrincipal
	}
	return revision, nil
}
