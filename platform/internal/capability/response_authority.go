package capability

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Recheck after a provider or ledger call, before disclosing its result. Billing
// already incurred must remain recorded even when permission has been revoked.
func (m *Module) currentCapability(w http.ResponseWriter, r *http.Request, op envelope) bool {
	if r.Context().Err() != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "caller execution ended; result unavailable", op.Context.TraceID)
		return false
	}
	if err := m.checkCurrentCapability(r, op); err != nil {
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current execution authorization denied", op.Context.TraceID)
		return false
	}
	return true
}

func (m *Module) checkCurrentCapability(r *http.Request, op envelope) error {
	if op.ToolApproval != nil {
		if m.toolConfirmationAuthority == nil || time.Now().Unix() >= op.ToolApproval.ExpiresAt || m.toolConfirmationAuthority.CheckApproval(r.Context(), *op.ToolApproval) != nil {
			return ErrToolApprovalDenied
		}
	}
	if m.publicKey == nil {
		return m.checkModelSkillBindings(r, op)
	}
	if err := m.validateContext(r, op.Context); err != nil {
		return err
	}
	policy, err := m.validatePolicy(r.Context(), op.Context)
	if err != nil || policy.Hash != op.Policy.Hash {
		return errors.New("current capability policy denied")
	}
	if err := m.validateLiveAuthority(r.Context(), op); err != nil {
		return err
	}
	return m.checkModelSkillBindings(r, op)
}

func (m *Module) currentResult(w http.ResponseWriter, r *http.Request, op envelope, result any) {
	if m.currentCapability(w, r, op) {
		m.ok(w, result, op.Context.TraceID)
	}
}

// Known truncated responses are priced and persisted once, but neither the
// first request nor an idempotent replay may advertise a complete answer.
func (m *Module) currentModelResult(w http.ResponseWriter, r *http.Request, op envelope, result map[string]any) {
	if !m.currentCapability(w, r, op) {
		return
	}
	if result["completion_status"] == "incomplete" {
		if result["finish_reason"] == "invalid_tool_calls" {
			m.knownUsageError(w, http.StatusBadGateway, "MODEL_FUNCTION_INVALID", "model function response violated published policy; known usage was recorded", op.Context.TraceID, result)
			return
		}
		m.knownUsageError(w, http.StatusBadGateway, "MODEL_OUTPUT_INCOMPLETE", "model output reached its token limit; known usage was recorded", op.Context.TraceID, result)
		return
	}
	fresh, ok := m.withRuntimeBudget(w, r, op, result)
	if ok {
		m.currentResult(w, r, op, fresh)
	}
}

// A known, billable incomplete response is still an error, but callers need
// its stable usage reference to reconcile the charge without exposing partial
// model text or invalid function arguments.
func (m *Module) knownUsageError(w http.ResponseWriter, status int, code, message, trace string, result map[string]any) {
	out := response{Code: 1, ErrorCode: code, Message: message, TraceID: trace}
	if stepID, ok := result["step_id"].(string); ok && stepID != "" {
		out.Data = map[string]string{"step_id": stepID}
	}
	m.write(w, status, out)
}

func (m *Module) withRuntimeBudget(w http.ResponseWriter, r *http.Request, op envelope, result map[string]any) (map[string]any, bool) {
	if budgets, ok := m.modelBudgets.(runtimeBudgetStatusReader); ok {
		ctx, err := m.skillExecutionContext(r, op)
		if err != nil {
			m.error(w, 403, "RUNTIME_BUDGET_SCOPE_DENIED", "current budget scope denied", op.Context.TraceID)
			return nil, false
		}
		bound, valid := ctx.Value(skillRuntimeContextKey{}).(skillRuntimeContext)
		if !valid {
			m.error(w, 403, "RUNTIME_BUDGET_SCOPE_DENIED", "current budget scope denied", op.Context.TraceID)
			return nil, false
		}
		budget, err := budgets.ReadRuntimeBudget(context.WithValue(ctx, runtimeBudgetContextKey{}, bound), bound.Scope)
		if err != nil {
			m.error(w, 503, "RUNTIME_BUDGET_UNAVAILABLE", "settled result budget status unavailable", op.Context.TraceID)
			return nil, false
		}
		// Volatile counters belong only to the authorized response. The immutable
		// model receipt cannot vary when concurrent root/child charges settle.
		fresh := make(map[string]any, len(result))
		for key, value := range result {
			if key != "run_budget" {
				fresh[key] = value
			}
		}
		fresh["run_budget"] = map[string]any{"version": budget.Version, "root_run_id": budget.RootRunID,
			"counters": budget.Counters, "exceeded": budget.Exceeded, "exhausted": budget.Counters.Exhausted()}
		return fresh, true
	}
	return result, true
}
