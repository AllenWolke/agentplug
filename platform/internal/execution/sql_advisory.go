package execution

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/sqlutil"
)

// lockExecutionAdvisory serializes capability state writes and lease mutations
// for one Run without holding the execution row itself. Shared acquisitions are
// the checkpoint/capability read fences; exclusive acquisitions are lease
// acquisition, heartbeat, transition, resume and cancellation paths. Every
// caller takes this advisory before any run/session row lock so the lock order
// stays constant (advisory first, row second). The advisory is transaction
// scoped and released automatically on commit or rollback.
func lockExecutionAdvisory(ctx context.Context, tx *sql.Tx, runID string, shared bool) error {
	function := "pg_advisory_xact_lock"
	if shared {
		function = "pg_advisory_xact_lock_shared"
	}
	_, err := tx.ExecContext(ctx, sqlutil.Bind("SELECT "+function+"(hashtext(?))"), runID)
	return err
}
