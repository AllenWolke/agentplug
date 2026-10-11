package main

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

// Evaluation case parents belong to the product Run store. Prove its actual
// frozen case, creator, lease and dual authority before fencing the child;
// a nonempty parent ID alone must never skip the execution ancestry boundary.
func lockCheckpointAncestors(ctx context.Context, tx *sql.Tx, runs *execution.SQLStore, evaluation *evaluationExecutionAuthority, scope sharedkernel.Scope) error {
	if evaluationBudgetCandidate(ctx, runs, scope) {
		if evaluation == nil {
			return usagecost.ErrBudgetScopeMismatch
		}
		_, err := evaluation.LockBudgetParentTx(ctx, tx, scope, true)
		return err
	}
	return lockBudgetAncestors(ctx, tx, runs, scope)
}
