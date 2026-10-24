package execution

import (
	"context"
	"errors"

	platformruntime "github.com/lexagent/platform/internal/runtime"
	"github.com/lexagent/platform/internal/sharedkernel"
)

// ErrExecutionOutcomeUnconfirmed preserves the lease when side effects or an
// admitted descendant have not reached an authoritative settled terminal state.
var ErrExecutionOutcomeUnconfirmed = errors.New("execution outcome effects unconfirmed")

// CheckRetryOutcomeQuiescence checks the entire admitted tree under the same
// execution lock used by external-effect admission. It grants no new lease.
func (s *SQLStore) CheckRetryOutcomeQuiescence(ctx context.Context, scope sharedkernel.Scope) error {
	if ctx == nil || scope.ValidateTrusted() != nil || s.terminalOutcomeFence == nil {
		return ErrExecutionOutcomeUnconfirmed
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The fence is a read-only consistency check. It takes the same per-Run
	// shared advisory as capability state saves instead of a row FOR UPDATE, so
	// a concurrent heartbeat/transition does not turn a legitimate check into a
	// false "effects unconfirmed" that cancels the run.
	if err := lockExecutionAdvisory(ctx, tx, scope.RunID, true); err != nil {
		return err
	}
	run, err := readExecutionRun(ctx, tx, scope.RunID, "")
	if err != nil {
		return err
	}
	if run.Scope != scope || run.Status != platformruntime.StatusRunning {
		return ErrExecutionOutcomeUnconfirmed
	}
	if err := s.terminalOutcomeFence(ctx, tx, scope); err != nil {
		return err
	}
	return tx.Commit()
}
