package capability

import (
	"context"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type runtimeBudgetContextKey struct{}

// Only the signed capability gateway installs this binding; payloads cannot
// supply it. Composition validates its lease inside the budget transaction.
func RuntimeBudgetExecutionAuthority(ctx context.Context, scope sharedkernel.Scope) (sharedkernel.ExecutionLeaseBinding, policyasset.Snapshot, error) {
	bound, ok := ctx.Value(runtimeBudgetContextKey{}).(skillRuntimeContext)
	if !ok || bound.Scope != scope || bound.Check == nil || bound.Check(ctx) != nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	return bound.Lease, bound.Policy, nil
}

type runtimeBudgetAdmissionStore interface{ RequiresExecutionAdmission() bool }

type runtimeBudgetStatusReader interface {
	ReadRuntimeBudget(context.Context, sharedkernel.Scope) (usagecost.RunTreeBudgetReceipt, error)
}
