package capability

import (
	"context"
	"math"
	"net/http"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/usagecost"
)

type modelBudgetAdmissionKey struct{}
type modelBudgetAdmission struct {
	Execution skillRuntimeContext
	Request   usagecost.ModelBudgetRequest
	Tokens    int64
}

// ModelBudgetExecutionAuthority repeats the private binding check for the
// verified scope during the root budget transaction's admission checks.
func ModelBudgetExecutionAuthority(ctx context.Context, scope sharedkernel.Scope) (sharedkernel.ExecutionLeaseBinding, policyasset.Snapshot, error) {
	bound, ok := ctx.Value(modelBudgetAdmissionKey{}).(modelBudgetAdmission)
	if !ok || bound.Execution.Scope != scope || bound.Execution.Check == nil {
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	if err := bound.Execution.Check(ctx); err != nil {
		if ctx.Err() != nil {
			return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, ctx.Err()
		}
		if budgetAdmissionDeferred(err) {
			return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, err
		}
		return sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, usagecost.ErrBudgetScopeMismatch
	}
	return bound.Execution.Lease, bound.Execution.Policy, nil
}

// ModelBudgetAdmissionAuthority is a composition Port. Only the signed gateway
// can install this private binding; JSON or provider metadata cannot supply it.
func ModelBudgetAdmissionAuthority(ctx context.Context, request usagecost.ModelBudgetRequest) (sharedkernel.Scope, sharedkernel.ExecutionLeaseBinding, policyasset.Snapshot, int64, error) {
	bound, ok := ctx.Value(modelBudgetAdmissionKey{}).(modelBudgetAdmission)
	if !ok || bound.Request != request || bound.Tokens < 0 || bound.Execution.Check == nil || bound.Execution.Scope.ValidateTrusted() != nil {
		return sharedkernel.Scope{}, sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, 0, usagecost.ErrBudgetScopeMismatch
	}
	if err := bound.Execution.Check(ctx); err != nil {
		if ctx.Err() != nil {
			return sharedkernel.Scope{}, sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, 0, ctx.Err()
		}
		if budgetAdmissionDeferred(err) {
			return sharedkernel.Scope{}, sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, 0, err
		}
		return sharedkernel.Scope{}, sharedkernel.ExecutionLeaseBinding{}, policyasset.Snapshot{}, 0, usagecost.ErrBudgetScopeMismatch
	}
	return bound.Execution.Scope, bound.Execution.Lease, bound.Execution.Policy, bound.Tokens, nil
}

func (m *Module) bindModelBudgetAdmission(r *http.Request, op envelope, request usagecost.ModelBudgetRequest, messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}, maxTokens int) (context.Context, error) {
	ctx, err := m.skillExecutionContext(r, op)
	if err != nil {
		return nil, err
	}
	bound, ok := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
	if !ok || bound.Scope.RunID != request.RunID || bound.Scope.TenantID != request.Scope.TenantID || bound.Scope.DepartmentID != request.Scope.DepartmentID || bound.Scope.ApplicationID != request.Scope.ApplicationID || bound.Scope.AgentID != request.Scope.AgentID || bound.Scope.AgentVersionID != request.Scope.AgentVersionID || maxTokens <= 0 {
		return nil, usagecost.ErrBudgetScopeMismatch
	}
	input, err := conservativeInputTokenEstimate(messages)
	if err != nil || int64(maxTokens) > math.MaxInt64-input {
		return nil, usagecost.ErrInvalidUsage
	}
	return context.WithValue(ctx, modelBudgetAdmissionKey{}, modelBudgetAdmission{Execution: bound, Request: request, Tokens: input + int64(maxTokens)}), nil
}
