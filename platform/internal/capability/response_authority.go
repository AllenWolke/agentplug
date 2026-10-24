package capability

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/modelgovernance"
)

// Recheck after a provider or ledger call, before disclosing its result. Billing
// already incurred must remain recorded even when permission has been revoked.
func (m *Module) currentCapability(w http.ResponseWriter, r *http.Request, op envelope) bool {
	if r.Context().Err() != nil {
		if m.capabilityCheckUnavailable(w, op, r.Context().Err()) {
			return false
		}
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "caller execution ended; result unavailable", op.Context.TraceID)
		return false
	}
	if err := m.checkCurrentCapability(r, op); err != nil {
		if m.capabilityCheckUnavailable(w, op, err) {
			return false
		}
		m.error(w, http.StatusForbidden, "CAPABILITY_DENIED", "current execution authorization denied", op.Context.TraceID)
		return false
	}
	return true
}

func (m *Module) checkCurrentCapability(r *http.Request, op envelope) error {
	if op.ToolApproval != nil {
		if m.toolConfirmationAuthority == nil || time.Now().Unix() >= op.ToolApproval.ExpiresAt {
			return ErrToolApprovalDenied
		}
		if err := m.toolConfirmationAuthority.CheckApproval(r.Context(), *op.ToolApproval); err != nil {
			return err
		}
	}
	if m.publicKey == nil {
		return m.checkModelSkillBindings(r, op)
	}
	if err := m.validateContext(r, op.Context); err != nil {
		return err
	}
	policy, err := m.validatePolicy(r.Context(), op.Context)
	if budgetAdmissionDeferred(err) {
		return err
	}
	if err != nil || policy.Hash != op.Policy.Hash {
		return errors.New("current capability policy denied")
	}
	var authorityErr error
	if op.admissionFacts != nil {
		authorityErr = m.validateLiveAuthorityWithFacts(r.Context(), op, op.admissionFacts)
	} else {
		authorityErr = m.validateLiveAuthority(r.Context(), op)
	}
	if authorityErr != nil {
		return authorityErr
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
	if !m.currentModelAuthorization(w, r, op, result) {
		return
	}
	if result["completion_status"] == "incomplete" {
		if result["finish_reason"] == "invalid_tool_calls" {
			m.knownUsageError(w, http.StatusBadGateway, "MODEL_FUNCTION_INVALID", "model function response violated published policy; known usage was recorded", op.Context.TraceID, result)
			return
		}
		message := "model output reached its token limit; known usage was recorded"
		if result["finish_reason"] == "invalid_response_schema" {
			message = "model output violated the published response schema; known usage was recorded"
		}
		m.knownUsageError(w, http.StatusBadGateway, "MODEL_OUTPUT_INCOMPLETE", message, op.Context.TraceID, result)
		return
	}
	fresh, ok := m.withRuntimeBudget(w, r, op, result)
	if ok {
		m.currentResult(w, r, op, fresh)
	}
}

// A completed billable response survives revocation in the ledger, but model
// approval/access must still be current before its text or functions are read.
func (m *Module) currentModelAuthorization(w http.ResponseWriter, r *http.Request, op envelope, result map[string]any) bool {
	if m.modelAccess == nil {
		return true
	}
	scope := scopeFromHarness(op.Context)
	selected, err := m.modelAccess.ResolveModel(r.Context(), scope, op.Policy.Model.ModelVersionID)
	if err == nil && (selected.ModelVersionID != op.Policy.Model.ModelVersionID || !sameModelSelection(op.Policy.Model.Provider, op.Policy.Model.Model, selected)) {
		err = modelgovernance.ErrModelAccessDenied
	}
	if err == nil && result["routing"] != nil {
		resolver, ok := m.modelAccess.(modelgateway.RoutingMetadataResolver)
		if !ok || op.Policy.Model.Routing == nil {
			err = ErrModelRouteUnavailable
		} else {
			metadata, metadataErr := resolver.ResolveRoutingModel(r.Context(), scope, op.Policy.Model.ModelVersionID)
			err = metadataErr
			member := false
			if err == nil {
				for _, candidate := range op.Policy.Model.Routing.Candidates {
					member = member || candidate.ModelVersionID == selected.ModelVersionID && candidate.CapabilitySHA256 == metadata.CapabilitySHA256()
				}
				if !member {
					err = modelgovernance.ErrModelAccessDenied
				}
			}
		}
	}
	if err != nil {
		status, code := modelRouteError(err)
		m.error(w, status, code, "current model authorization unconfirmed", op.Context.TraceID)
		return false
	}
	return true
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
		fresh := make(map[string]any, len(result)+1)
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
