package execution

import (
	"bytes"
	"context"
	"database/sql"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CancellationExecutionRevision resolves a stop-only generation under the
// current Run fence. A waiting outcome changes the head, but not the dispatch.
// 在当前 Run 锁内核对只追加投递账本；waiting Head 不等于原执行世代。
func (s *SQLStore) CancellationExecutionRevision(ctx context.Context, pending platformruntime.Run) (uint64, error) {
	if s == nil || s.db == nil || ctx == nil || pending.Scope.ValidateTrusted() != nil || pending.ID != pending.Scope.RunID || pending.LeaseToken == "" ||
		(pending.Status != platformruntime.StatusCancelling && pending.Status != platformruntime.StatusRecovering) {
		return 0, platformruntime.ErrInvalidRequest
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	actual, err := readExecutionRun(ctx, tx, pending.ID, " FOR UPDATE")
	if err != nil {
		return 0, err
	}
	if actual.Scope != pending.Scope || actual.Status != pending.Status || actual.Revision != pending.Revision || actual.LeaseToken != pending.LeaseToken ||
		actual.AgentEndpoint != pending.AgentEndpoint || actual.IdempotencyKey != pending.IdempotencyKey || !bytes.Equal(actual.RequestJSON, pending.RequestJSON) || !bytes.Equal(actual.ResumeInputJSON, pending.ResumeInputJSON) {
		return 0, platformruntime.ErrRevisionConflict
	}
	revision, err := s.cancellationExecutionRevisionTx(ctx, tx, actual)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return revision, nil
}

// The caller already owns the exact Run lock. Reusing this port avoids a
// second connection waiting on its own cancellation transaction.
func (s *SQLStore) cancellationExecutionRevisionTx(ctx context.Context, tx *sql.Tx, actual platformruntime.Run) (uint64, error) {
	var command platformruntime.DispatchCommand
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT run_id,revision,operation,body_hash,policy_hash FROM platform_execution_dispatch_command WHERE run_id=? FOR SHARE`), actual.ID).
		Scan(&command.RunID, &command.Revision, &command.Operation, &command.BodyHash, &command.PolicyHash)
	if err != nil {
		return 0, err
	}
	if command.Validate() != nil || command.RunID != actual.ID || command.Revision >= actual.Revision {
		return 0, platformruntime.ErrInvalidRequest
	}
	// Old projections are insufficient. The append-only journal must tie this
	// exact command to the retained lease, request and approved resume envelope.
	// 旧投影不能单独作证；只追加账本必须匹配保留租约、请求及审核输入摘要。
	var recorded bool
	err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS(SELECT 1 FROM platform_execution_generation_dispatch_journal
 WHERE run_id=? AND protocol_epoch=? AND protocol_version=? AND execution_revision=? AND operation=? AND body_hash=? AND policy_hash=?
 AND lease_token_hash=? AND request_hash=? AND resume_input_hash=?)`), actual.ID, generationJournalProtocolEpoch, generationJournalProtocolVersion,
		command.Revision, command.Operation, command.BodyHash, command.PolicyHash, generationJournalHash([]byte(actual.LeaseToken)),
		generationJournalHash(actual.RequestJSON), generationJournalHash(actual.ResumeInputJSON)).Scan(&recorded)
	if err != nil {
		return 0, err
	}
	if !recorded {
		return 0, platformruntime.ErrLeaseConflict
	}
	return command.Revision, nil
}
