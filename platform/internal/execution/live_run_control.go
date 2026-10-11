package execution

import (
	"context"
	"database/sql"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CheckLiveRunTx is a non-secret projection of the actual Run/session fence.
// Callers must independently verify scope ownership and root-first lock order.
func (s *SQLStore) CheckLiveRunTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope) error {
	if s == nil || tx == nil || scope.ValidateTrusted() != nil {
		return platformruntime.ErrLeaseConflict
	}
	var matched int
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT 1 FROM platform_execution_run r JOIN platform_execution_session_lease l ON l.session_key=? AND l.run_id=r.run_id AND l.lease_token=r.lease_token WHERE r.run_id=? AND r.status='running' AND r.lease_token<>'' AND r.lease_until>clock_timestamp() AND l.lease_until>clock_timestamp() FOR SHARE OF r,l`), platformruntime.SessionExecutionKey(scope), scope.RunID).Scan(&matched)
	if errors.Is(err, sql.ErrNoRows) {
		return platformruntime.ErrLeaseConflict
	}
	return err
}
