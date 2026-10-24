package capability

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type modelGenerateInput struct {
	Texts              []string                     `json:"texts"`
	EmbeddingPurpose   string                       `json:"input_purpose,omitempty"`
	Messages           []modelgateway.Message       `json:"messages"`
	FunctionNames      []string                     `json:"function_names"`
	SkillBindings      map[string]SkillModelBinding `json:"skill_bindings"`
	PromptTemplateHash string                       `json:"prompt_template_hash"`
	IdempotencyKey     string                       `json:"idempotency_key"`
	Temperature        float64                      `json:"temperature"`
	MaxTokens          int                          `json:"max_tokens"`
	RequireJSON        bool                         `json:"require_json,omitempty"`
	ResponseSchema     json.RawMessage              `json:"response_schema,omitempty"`
	ResponseSchemaMode string                       `json:"response_schema_mode,omitempty"`
	DeadlineMS         int64                        `json:"deadline_ms,omitempty"`
}

// This metadata lives inside the immutable route decision, so CAS fixes the
// predecessor, proof, model and price together before the next physical send.
type ModelRouteFallback struct {
	Version                string `json:"version"`
	LogicalKeySHA256       string `json:"logical_key_sha256"`
	Attempt                int    `json:"attempt"`
	PreviousDecisionSHA256 string `json:"previous_decision_sha256"`
	PreviousOutcomeSHA256  string `json:"previous_outcome_sha256"`
	MinimumQualityRank     int    `json:"minimum_quality_rank"`
}

type routeFallbackContext struct {
	Fallback *ModelRouteFallback
	Excluded []string
}
type modelRouteFallbackKey struct{}
type modelRouteTraversalKey struct{}

// Trusted recovery reader. Public receipt reads hide incomplete internals.
func (s *memoryModelInvocationStore) GetBillingRecord(ctx context.Context, scope, key string) (ModelInvocation, error) {
	if err := ctx.Err(); err != nil {
		return ModelInvocation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.records[scope+"\x00"+key]
	if !found {
		return ModelInvocation{}, ErrModelInvocationConflict
	}
	return cloneInvocation(record), nil
}

type fallbackRoutingMetadata struct {
	modelgateway.RoutingMetadataResolver
	excluded []string
}

func (r fallbackRoutingMetadata) ResolveRoutingModel(ctx context.Context, scope sharedkernel.Scope, model string) (modelgateway.RoutingMetadata, error) {
	for _, id := range r.excluded {
		if id == model {
			return modelgateway.RoutingMetadata{}, ErrModelRouteCandidateUnavailable
		}
	}
	return r.RoutingMetadataResolver.ResolveRoutingModel(ctx, scope, model)
}

func validModelRouteFallback(f *ModelRouteFallback) bool {
	return f == nil || f.Version == "model-route-fallback/v1" && isRouteSHA(f.LogicalKeySHA256) && f.Attempt >= 1 && f.Attempt <= 2 &&
		isRouteSHA(f.PreviousDecisionSHA256) && isRouteSHA(f.PreviousOutcomeSHA256) && f.MinimumQualityRank >= 1 && f.MinimumQualityRank <= 3
}

func physicalRouteAttemptKey(logical string, attempt int) string {
	if attempt == 0 {
		return logical
	}
	return "route-fallback-" + modelRouteHash(struct {
		Logical string
		Attempt int
	}{logical, attempt})
}

func routeInput(in modelGenerateInput) ModelRouteRequest {
	return ModelRouteRequest{Messages: in.Messages, FunctionNames: in.FunctionNames, MaxTokens: in.MaxTokens, RequireJSON: in.RequireJSON,
		ResponseSchema: in.ResponseSchema, ResponseSchemaMode: in.ResponseSchemaMode, DeadlineMS: in.DeadlineMS}
}

func modelDeadlineFingerprint(input string, deadline int64) string {
	if deadline == 0 {
		return input
	}
	return modelRouteHash(struct {
		Input      string
		DeadlineMS int64
	}{input, deadline})
}

func routeNativeFingerprint(op envelope, in modelGenerateInput, route StoredModelRoute) string {
	model := op.Policy.Model
	model.Model, model.ModelVersionID = route.Decision.ModelKey, route.Decision.ModelVersionID
	fp, _ := modelCommandFingerprint(in.Messages, in.Temperature, in.MaxTokens, in.PromptTemplateHash, model, in.FunctionNames, false, in.SkillBindings)
	if in.RequireJSON {
		fp = modelPurposeFingerprint(fp, "json_object")
	}
	raw, mode, err := modelgateway.NormalizeResponseSchema(in.ResponseSchema, in.ResponseSchemaMode, in.RequireJSON, in.FunctionNames)
	if err != nil {
		return ""
	}
	return modelDeadlineFingerprint(modelResponseSchemaFingerprint(fp, raw, mode), in.DeadlineMS)
}

// Only a completed, metered incomplete response or the existing signed system
// no-send proof can advance. HTTP status alone never proves a safe retry.
func (m *Module) routeFallbackProof(ctx context.Context, op envelope, in modelGenerateInput, route StoredModelRoute) (string, bool, error) {
	store, ok := m.modelStore.(modelReceiptReadStore)
	if !ok {
		return "", false, ErrModelRouteUnavailable
	}
	scope := modelSelectionScopeHash(scopeFromHarness(op.Context))
	record, found, err := store.LookupModelInvocation(ctx, scope, in.IdempotencyKey)
	if err != nil || !found {
		return "", false, err
	}
	if record.Fingerprint != routeNativeFingerprint(op, in, route) {
		return "", false, ErrModelInvocationConflict
	}
	if record.Status == "completed" && record.Response["completion_status"] == "incomplete" {
		if _, err := routeSummaryReceipt(route, record, true); err != nil {
			return "", false, err
		}
		routing, _ := record.Response["routing"].(map[string]any)
		if routing["decision_sha256"] != route.DecisionSHA256 {
			return "", false, ErrModelInvocationConflict
		}
		return modelRouteHash(record.Response), true, nil
	}
	if record.Status != "failed" {
		return "", false, nil
	}
	billing, ok := m.modelStore.(interface {
		GetBillingRecord(context.Context, string, string) (ModelInvocation, error)
	})
	if !ok {
		return "", false, ErrModelRouteUnavailable
	}
	record, err = billing.GetBillingRecord(ctx, scope, in.IdempotencyKey)
	if err != nil {
		return "", false, err
	}
	if record.Status != "failed" || record.Fingerprint != routeNativeFingerprint(op, in, route) || record.Recovery == nil || !record.Recovery.Unsent ||
		record.Recovery.PriceID != route.Decision.Price.ID || record.Recovery.Decision == nil || record.Recovery.Reservation.Fingerprint != record.Fingerprint {
		return "", false, nil
	}
	if !recordedSystemUnsentProof(record) {
		return "", false, nil
	}
	return modelRouteHash(record.Recovery), true, nil
}

func nextRouteFallback(logical string, index int, prior routeFallbackContext, route StoredModelRoute, proof string, p policyasset.ModelRoutingPolicy) routeFallbackContext {
	rank := 0
	if prior.Fallback != nil {
		rank = prior.Fallback.MinimumQualityRank
	}
	for _, c := range p.Candidates {
		if c.ModelVersionID == route.Decision.ModelVersionID && policyasset.ModelComplexityRank(c.MaxComplexity) > rank {
			rank = policyasset.ModelComplexityRank(c.MaxComplexity)
		}
	}
	return routeFallbackContext{Fallback: &ModelRouteFallback{Version: "model-route-fallback/v1", LogicalKeySHA256: modelRouteHash(logical), Attempt: index + 1,
		PreviousDecisionSHA256: route.DecisionSHA256, PreviousOutcomeSHA256: proof, MinimumQualityRank: rank},
		Excluded: append(append([]string(nil), prior.Excluded...), route.Decision.ModelVersionID)}
}

func copyModelResponse(w http.ResponseWriter, captured *modelCallResponse) {
	for key, values := range captured.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	status := captured.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(captured.body.Bytes())
}

func (m *Module) generateAuthorized(w http.ResponseWriter, r *http.Request, op envelope) {
	p := op.Policy.Model.Routing
	if r.URL.Path == "/internal/model/embed" || p == nil || p.Availability == nil || p.Validate() != nil {
		m.generateAuthorizedOnce(w, r, op)
		return
	}
	var in modelGenerateInput
	if json.Unmarshal(op.Input, &in) != nil || len(in.Messages) == 0 || !validSkillModelBindings(in.SkillBindings) {
		m.generateAuthorizedOnce(w, r, op)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), skillModelBindingsKey{}, in.SkillBindings))
	if !m.currentCapability(w, r, op) {
		return
	}
	if in.MaxTokens == 0 {
		in.MaxTokens = op.Policy.Model.MaxTokens
	}
	logical := in.IdempotencyKey
	if logical == "" {
		logical = op.Context.IdempotencyKey
	}
	if logical == "" {
		logical = op.Context.RequestID + ":model.generate"
	}
	if strings.HasPrefix(logical, "route-fallback-") {
		m.error(w, 400, "INVALID_REQUEST", "reserved model attempt identity", op.Context.TraceID)
		return
	}
	if p.Availability.Version == "model-route-availability/v2" {
		in.IdempotencyKey = logical
		m.generateResilientAuthorized(w, r, op, in)
		return
	}
	var previous routeFallbackContext
	for index := 0; index < p.Availability.MaxAttempts; index++ {
		if r.Context().Err() != nil {
			m.error(w, 408, "MODEL_CALL_CANCELLED", "model request cancelled", op.Context.TraceID)
			return
		}
		in.IdempotencyKey = physicalRouteAttemptKey(logical, index)
		ctx := context.WithValue(r.Context(), modelRouteFallbackKey{}, previous)
		traversal := context.WithValue(ctx, modelRouteTraversalKey{}, true)
		check := op
		route, automatic, err := m.resolveInvocationRoute(traversal, &check, in.IdempotencyKey, routeInput(in), in.Temperature, in.PromptTemplateHash, in.SkillBindings, true)
		if err != nil {
			status, code := modelRouteError(err)
			m.error(w, status, code, "model attempt lookup denied", op.Context.TraceID)
			return
		}
		if !automatic {
			m.generateAuthorizedOnce(w, r, op)
			return
		}
		proof, safe := "", false
		if route != nil {
			proof, safe, err = m.routeFallbackProof(ctx, op, in, *route)
			if err != nil {
				status, code := modelRouteError(err)
				m.error(w, status, code, "previous model outcome could not be verified", op.Context.TraceID)
				return
			}
		}
		var captured *modelCallResponse
		if !safe {
			if route != nil {
				read, ok := m.modelStore.(modelReceiptReadStore)
				if !ok {
					m.error(w, 503, "MODEL_ROUTING_UNAVAILABLE", "model outcome store unavailable", op.Context.TraceID)
					return
				}
				prior, found, readErr := read.LookupModelInvocation(ctx, modelSelectionScopeHash(scopeFromHarness(op.Context)), in.IdempotencyKey)
				if readErr != nil {
					m.error(w, 503, "MODEL_ROUTING_UNAVAILABLE", "model outcome unavailable", op.Context.TraceID)
					return
				}
				if found && prior.Status == "failed" {
					m.error(w, 409, "MODEL_ROUTE_RETRY_NOT_AUTHORIZED", "previous failure has no verified automatic retry proof", op.Context.TraceID)
					return
				}
			}
			attempt := op
			attempt.Input, _ = json.Marshal(in)
			captured = &modelCallResponse{header: make(http.Header)}
			m.generateAuthorizedOnce(captured, r.WithContext(ctx), attempt)
			check = op
			route, _, err = m.resolveInvocationRoute(traversal, &check, in.IdempotencyKey, routeInput(in), in.Temperature, in.PromptTemplateHash, in.SkillBindings, true)
			if err != nil || route == nil {
				copyModelResponse(w, captured)
				return
			}
			proof, safe, err = m.routeFallbackProof(ctx, op, in, *route)
			if err != nil || !safe {
				copyModelResponse(w, captured)
				return
			}
		}
		if index+1 == p.Availability.MaxAttempts {
			if captured != nil {
				copyModelResponse(w, captured)
			} else {
				m.error(w, 502, "MODEL_ROUTE_ATTEMPTS_EXHAUSTED", "published model attempt limit reached", op.Context.TraceID)
			}
			return
		}
		previous = nextRouteFallback(logical, index, previous, *route, proof, *p)
	}
}

// Read-only traversal follows durable proofs; it never creates the next route.
func (m *Module) readModelRouteAttempt(ctx context.Context, op envelope, in modelGenerateInput) (context.Context, modelGenerateInput, error) {
	p := op.Policy.Model.Routing
	if p == nil || p.Availability == nil {
		return ctx, in, nil
	}
	if p.Validate() != nil {
		return ctx, in, policyasset.ErrMissingPolicy
	}
	if p.Availability.Version == "model-route-availability/v2" {
		return m.readResilientModelAttempt(ctx, op, in)
	}
	logical := in.IdempotencyKey
	var previous routeFallbackContext
	for index := 0; index < p.Availability.MaxAttempts; index++ {
		in.IdempotencyKey = physicalRouteAttemptKey(logical, index)
		current := context.WithValue(ctx, modelRouteFallbackKey{}, previous)
		check := op
		route, automatic, err := m.resolveInvocationRoute(context.WithValue(current, modelRouteTraversalKey{}, true), &check, in.IdempotencyKey,
			routeInput(in), in.Temperature, in.PromptTemplateHash, in.SkillBindings, true)
		if err != nil || !automatic || route == nil {
			return current, in, err
		}
		proof, safe, err := m.routeFallbackProof(current, op, in, *route)
		if err != nil || !safe || index+1 == p.Availability.MaxAttempts {
			return current, in, err
		}
		previous = nextRouteFallback(logical, index, previous, *route, proof, *p)
	}
	return ctx, in, ErrModelRouteUnavailable
}
