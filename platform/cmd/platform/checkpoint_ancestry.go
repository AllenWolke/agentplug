package main

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/execution"
	"github.com/lexagent/platform/internal/identity"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

// Match budget admission's order on every protected State/Memory/effect path.
// Evaluation locks its product parent before IAM; ordinary execution locks
// IAM before root-first execution ancestry. The routing hint conveys no grant:
// the Evaluation branch still requires full frozen-case and live-parent proof.
func lockCheckpointContinuity(ctx context.Context, tx *sql.Tx, iam *identity.SQLStore, runs *execution.SQLStore, evaluation *evaluationExecutionAuthority, scope sharedkernel.Scope) error {
	if tx == nil || iam == nil || runs == nil {
		return usagecost.ErrBudgetScopeMismatch
	}
	if evaluationBudgetCandidate(ctx, runs, scope) {
		return lockCheckpointAncestors(ctx, tx, runs, evaluation, scope)
	}
	if err := iam.AcquirePermissionReadContinuity(ctx, tx); err != nil {
		return err
	}
	return lockBudgetAncestors(ctx, tx, runs, scope)
}

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
