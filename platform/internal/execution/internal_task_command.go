package execution

import (
	"context"
	"database/sql"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// RecordInternalTaskCommandTx composes command publication with the caller's
// current IAM fence. It owns only execution tables and requires the exact live
// task lease. Composition derives digests from the stored immutable command.
func (s *SQLStore) RecordInternalTaskCommandTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, token string, revision uint64, command platformruntime.DispatchCommand) error {
	if command.Validate() != nil || command.RunID != scope.RunID || command.Revision != revision {
		return platformruntime.ErrLeaseConflict
	}
	if err := s.CheckTaskLeaseTx(ctx, tx, scope, token, revision); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_dispatch_command AS c(run_id,revision,operation,body_hash,policy_hash) VALUES (?,?,?,?,?) ON CONFLICT (run_id) DO UPDATE SET revision=EXCLUDED.revision,operation=EXCLUDED.operation,body_hash=EXCLUDED.body_hash,policy_hash=EXCLUDED.policy_hash WHERE c.revision<EXCLUDED.revision OR (c.revision=EXCLUDED.revision AND c.operation=EXCLUDED.operation AND c.body_hash=EXCLUDED.body_hash AND c.policy_hash=EXCLUDED.policy_hash)`), command.RunID, command.Revision, command.Operation, command.BodyHash, command.PolicyHash)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return platformruntime.ErrRevisionConflict
	}
	return nil
}
