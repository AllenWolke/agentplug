package main

import (
	"context"
	"database/sql"

	"github.com/lexagent/platform/internal/agentcoordination"
	platformruntime "github.com/lexagent/platform/internal/runtime"
)

// Control survives revocation but conveys no new execution permission. The
// durable parent must be cancelling and this exact persisted case must match
// its frozen suite, input, creator, budget and depth-zero invocation identity.
func (a evaluationExecutionAuthority) AuthorizeCompletedCompensationTx(ctx context.Context, tx *sql.Tx, run platformruntime.Run) error {
	if tx == nil || a.route.runs == nil || run.Scope.ParentRunID == "" || (run.Status != platformruntime.StatusSucceeded && run.Status != platformruntime.StatusFailed) || run.LeaseToken != "" || !run.LeaseUntil.IsZero() {
		return agentcoordination.ErrDenied
	}
	parent, err := a.readBudgetParentTx(ctx, tx, run.Scope, false, true)
	if err != nil {
		return err
	}
	if parent.resource.Status != "cancelling" && parent.resource.Status != "cancelled" {
		return agentcoordination.ErrDenied
	}
	facts, err := a.route.runs.BudgetRunReadTx(ctx, tx, run.ID)
	if err != nil || facts.Scope != run.Scope || facts.Status != run.Status || facts.Revision != run.Revision || facts.HasLease {
		return agentcoordination.ErrDenied
	}
	_, err = a.VerifyBudgetTx(ctx, tx, run.Scope, facts, parent, false)
	return err
}
