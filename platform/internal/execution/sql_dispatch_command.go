package execution

import (
	"context"
	"database/sql"
	"errors"
	"time"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

func (s *SQLStore) RecordDispatchCommand(command platformruntime.DispatchCommand, token string) error {
	return s.RecordDispatchCommandWithTransport(command, token, "agent-gateway-v2")
}

// RecordDispatchCommandWithTransport appends the immutable gateway dispatch
// fact before maintaining the legacy latest-command projection in the same
// transaction. The selected transport is supplied by the dispatcher after
// target resolution.
func (s *SQLStore) RecordDispatchCommandWithTransport(command platformruntime.DispatchCommand, token, transport string) error {
	if err := command.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	run, err := s.GetContext(ctx, command.RunID)
	if err != nil {
		return err
	}
	if run.Revision != command.Revision || token == "" || run.LeaseToken != token {
		return platformruntime.ErrLeaseConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.RecordGenerationDispatchForRunTx(ctx, tx, run, transport, command.Operation, command.BodyHash, command.PolicyHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_execution_dispatch_command(run_id,revision,operation,body_hash,policy_hash) VALUES (?,?,?,?,?) ON CONFLICT (run_id) DO UPDATE SET revision=EXCLUDED.revision,operation=EXCLUDED.operation,body_hash=EXCLUDED.body_hash,policy_hash=EXCLUDED.policy_hash`), command.RunID, command.Revision, command.Operation, command.BodyHash, command.PolicyHash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) GetDispatchCommand(id string) (platformruntime.DispatchCommand, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var c platformruntime.DispatchCommand
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,revision,operation,body_hash,policy_hash FROM platform_execution_dispatch_command WHERE run_id=?`), id).Scan(&c.RunID, &c.Revision, &c.Operation, &c.BodyHash, &c.PolicyHash)
	if errors.Is(err, sql.ErrNoRows) {
		return c, platformruntime.ErrRunNotFound
	}
	return c, err
}
