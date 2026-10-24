package capability

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type modelAttemptDeadlineKey struct{}
type modelExecutionReceiptKey struct{}

// Each iteration consumes a persisted disposition, never a guessed transport
// outcome. The native invocation store still owns admission and send fencing.
func (m *Module) generateResilientAuthorized(w http.ResponseWriter, r *http.Request, op envelope, input modelGenerateInput) {
	logical := input.IdempotencyKey
	if input.DeadlineMS < 0 || input.DeadlineMS > (1<<53)-1 {
		m.error(w, 400, "INVALID_REQUEST", "invalid model deadline", op.Context.TraceID)
		return
	}
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	check := op
	first, routed, err := m.resolveInvocationRoute(context.WithValue(r.Context(), modelRouteTraversalKey{}, true), &check, logical, routeInput(input), input.Temperature, input.PromptTemplateHash, input.SkillBindings, false)
	if err != nil {
		m.routeExecutionError(w, op, err)
		return
	}
	if !routed {
		m.generateAuthorizedOnce(w, r, op)
		return
	}
	store, ok := m.modelStore.(ModelRouteExecutionStore)
	if !ok || first == nil {
		m.routeExecutionError(w, op, ErrModelRouteUnavailable)
		return
	}
	p := *op.Policy.Model.Routing
	deadline := time.Now().UTC().Add(time.Duration(p.Availability.MaxAttempts*p.Availability.AttemptTimeoutSeconds) * time.Second)
	if input.DeadlineMS > 0 && time.UnixMilli(input.DeadlineMS).Before(deadline) {
		deadline = time.UnixMilli(input.DeadlineMS)
	}
	if original, ok := r.Context().Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	state, err := store.BeginModelRouteExecution(r.Context(), scope, logical, ModelRouteExecution{
		Version: "model-route-execution/v1", RequestFingerprint: first.RequestFingerprint, PolicySHA256: first.Decision.PolicySHA256,
		MaxAttempts: p.Availability.MaxAttempts, Revision: 1, Status: "active", Deadline: deadline, Steps: []ModelRouteExecutionStep{},
		RecoveryPolicy: &p,
	})
	if err != nil {
		m.routeExecutionError(w, op, err)
		return
	}
	// Bounded even under concurrent replay. A winning CAS can advance several
	// steps, but cannot create new allowance or rewrite the selected result.
	for turn := 0; turn <= state.MaxAttempts; turn++ {
		if r.Context().Err() != nil {
			m.error(w, 408, "MODEL_CALL_CANCELLED", "model request cancelled", op.Context.TraceID)
			return
		}
		if state.Status == "exhausted" {
			m.error(w, 502, "MODEL_ROUTE_ATTEMPTS_EXHAUSTED", "published model attempt limit reached; original accounting retained", op.Context.TraceID)
			return
		}
		if state.Status != "completed" && !time.Now().Before(state.Deadline) {
			m.error(w, 408, "MODEL_ROUTE_DEADLINE_EXCEEDED", "original model execution deadline reached", op.Context.TraceID)
			return
		}
		index := len(state.Steps)
		if state.Status == "completed" {
			index--
		}
		in := input
		in.IdempotencyKey = physicalRouteAttemptKey(logical, index)
		ctx := context.WithValue(r.Context(), modelRouteFallbackKey{}, modelRouteExecutionFallback(logical, state, index))
		check = op
		route, _, err := m.resolveInvocationRoute(ctx, &check, in.IdempotencyKey, routeInput(in), in.Temperature, in.PromptTemplateHash, in.SkillBindings, false)
		if err != nil || route == nil {
			if err == nil {
				err = ErrModelRouteUnavailable
			}
			m.routeExecutionError(w, op, err)
			return
		}
		fingerprint := routeNativeFingerprint(op, in, *route)
		if state.Status == "completed" {
			reader, ok := m.modelStore.(modelReceiptReadStore)
			if !ok {
				m.routeExecutionError(w, op, ErrModelRouteUnavailable)
				return
			}
			record, found, readErr := reader.LookupModelInvocation(ctx, scope, in.IdempotencyKey)
			step := state.Steps[index]
			if readErr != nil || !found || record.Status != "completed" || record.Fingerprint != fingerprint ||
				step.Fingerprint != fingerprint || step.DecisionSHA256 != route.DecisionSHA256 || modelRouteHash(record.Response) != step.OutcomeSHA256 {
				m.routeExecutionError(w, op, ErrModelInvocationConflict)
				return
			}
			result := cloneInvocation(record).Response
			result["route_execution"] = modelRouteExecutionReceipt(state)
			// The common response boundary rechecks live authority and reads the
			// current counters once. Reading them here as well only duplicates a
			// fenced SQL transaction; neither view belongs in the saved receipt.
			m.currentModelResult(w, r.WithContext(ctx), check, result)
			return
		}
		next, err := store.AdvanceModelRouteExecution(ctx, scope, logical, state, *route, fingerprint, p)
		if err == nil {
			state = next
			continue
		}
		if !errors.Is(err, ErrModelRouteOutcomePending) {
			m.routeExecutionError(w, op, err)
			return
		}
		attempt := op
		attempt.Input, _ = json.Marshal(in)
		captured := &modelCallResponse{header: make(http.Header)}
		attemptDeadline := time.Now().UTC().Add(time.Duration(p.Availability.AttemptTimeoutSeconds) * time.Second)
		if state.Deadline.Before(attemptDeadline) {
			attemptDeadline = state.Deadline
		}
		m.generateAuthorizedOnce(captured, r.WithContext(context.WithValue(ctx, modelAttemptDeadlineKey{}, attemptDeadline)), attempt)
		// The caller may disconnect at the same instant as a provider timeout.
		// Persist the already-finished physical disposition independently; this
		// context cannot authorize a further send or disclose the result.
		dispositionCtx, stopDisposition := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		next, err = store.AdvanceModelRouteExecution(dispositionCtx, scope, logical, state, *route, fingerprint, p)
		stopDisposition()
		if errors.Is(err, ErrModelRouteOutcomePending) || ctx.Err() != nil {
			copyModelResponse(w, captured)
			return
		}
		if err != nil {
			m.routeExecutionError(w, op, err)
			return
		}
		state = next
	}
	m.routeExecutionError(w, op, ErrModelRouteUnavailable)
}

func (m *Module) routeExecutionError(w http.ResponseWriter, op envelope, err error) {
	status, code := modelRouteError(err)
	m.error(w, status, code, "durable model execution could not advance", op.Context.TraceID)
}

func modelRouteExecutionReceipt(state ModelRouteExecution) map[string]any {
	pending := 0
	var retained int64
	for _, step := range state.Steps {
		if step.Disposition == "retained_unknown" {
			pending++
			retained += step.RetainedMicros
		}
	}
	return map[string]any{"version": "model-route-execution-receipt/v1", "status": state.Status, "attempts": len(state.Steps),
		"retained_unknown_attempts": pending, "retained_reservation_micros": retained, "execution_sha256": modelRouteHash(state)}
}

// Resume follows the immutable business choice even if an earlier provider
// subsequently finishes. Receipt lookup never creates a replacement attempt.
func (m *Module) readResilientModelAttempt(ctx context.Context, op envelope, in modelGenerateInput) (context.Context, modelGenerateInput, error) {
	store, ok := m.modelStore.(ModelRouteExecutionStore)
	if !ok {
		return ctx, in, ErrModelRouteUnavailable
	}
	logical := in.IdempotencyKey
	state, found, err := store.LookupModelRouteExecution(ctx, modelSelectionScopeHash(scopeFromHarness(op.Context)), logical)
	if err != nil || !found {
		return ctx, in, err
	}
	check := op
	first, _, err := m.resolveInvocationRoute(context.WithValue(ctx, modelRouteTraversalKey{}, true), &check, logical,
		routeInput(in), in.Temperature, in.PromptTemplateHash, in.SkillBindings, true)
	if err != nil {
		return ctx, in, err
	}
	if first == nil || state.RequestFingerprint != first.RequestFingerprint || state.PolicySHA256 != first.Decision.PolicySHA256 {
		return ctx, in, ErrModelInvocationConflict
	}
	index := len(state.Steps)
	if state.Status != "active" {
		index--
	}
	in.IdempotencyKey = physicalRouteAttemptKey(logical, index)
	ctx = context.WithValue(ctx, modelRouteFallbackKey{}, modelRouteExecutionFallback(logical, state, index))
	return context.WithValue(ctx, modelExecutionReceiptKey{}, state), in, nil
}
