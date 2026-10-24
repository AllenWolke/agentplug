package capability

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/lexagent/platform/internal/audit"
	"github.com/lexagent/platform/internal/modelgateway"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type ModelAttemptRecorder interface {
	Record(context.Context, audit.Event) error
}

func (m *Module) SetModelAttemptRecorder(recorder ModelAttemptRecorder) {
	m.modelAttemptRecorder = recorder
}

// This is explicitly not a physical provider attempt. The audited cause is
// known at the pre-invocation branch; accounting failure retains its proof.
func (m *Module) recordModelSendWindowExpired(ctx context.Context, scope sharedkernel.Scope, key, token string,
	selected modelgateway.Selection, embedding bool, closureErr error) {
	operation, closure := "generate", "closed_no_charge"
	if embedding {
		operation = "embed"
	}
	if closureErr != nil {
		closure = "awaiting_accounting"
	}
	value := struct {
		Version          string `json:"version"`
		Operation        string `json:"operation"`
		InvocationSHA256 string `json:"invocation_sha256"`
		ModelVersionID   string `json:"model_version_id"`
		Cause            string `json:"cause"`
		Accounting       string `json:"accounting"`
		ProviderInvoked  bool   `json:"provider_invoked"`
	}{"model-send-not-started/v1", operation, modelRouteHash(key), selected.ModelVersionID, "send_window_expired", closure, false}
	body, err := json.Marshal(value)
	if err != nil {
		return
	}
	log.Printf("model send not started run_id=%q detail=%s", scope.RunID, body)
	if m.modelAttemptRecorder == nil {
		return
	}
	event := audit.Event{ID: "model-unsent-" + modelRouteHash(struct{ Scope, Key, Token string }{modelSelectionScopeHash(scope), key, token}),
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID,
		AggregateType: "run", AggregateID: scope.RunID, Action: "model.send_not_started", Outcome: "not_submitted", Summary: string(body), CreatedAt: time.Now().UTC()}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := m.modelAttemptRecorder.Record(writeCtx, event); err != nil {
		log.Printf("model unsent audit unavailable run_id=%q invocation_sha256=%s", scope.RunID, value.InvocationSHA256)
	}
}

// Each physical invocation has one audited outcome. Connection attempts stay
// distinct from model failover attempts; unknown fees are never inferred here.
func (m *Module) recordModelAttempt(ctx context.Context, scope sharedkernel.Scope, key, token string,
	selected modelgateway.Selection, embedding bool, route *StoredModelRoute,
	trace *modelgateway.ProviderAttemptTrace, finished time.Time, invokeErr error, results ...modelgateway.GenerateResult) {
	operation, outcome, reason := "generate", "succeeded", ""
	if embedding {
		operation = "embed"
	}
	if invokeErr != nil {
		outcome, reason = "failed", modelProviderErrorKind(invokeErr)
	}
	stage, cause, connection := modelgateway.SafeProviderTransportDetail(invokeErr)
	value := struct {
		Version           string                                    `json:"version"`
		Operation         string                                    `json:"operation"`
		InvocationSHA256  string                                    `json:"invocation_sha256"`
		ModelVersionID    string                                    `json:"model_version_id"`
		ModelKey          string                                    `json:"model_key"`
		ProviderID        string                                    `json:"provider_id"`
		PriceVersionID    string                                    `json:"price_version_id,omitempty"`
		Outcome           string                                    `json:"outcome"`
		ErrorKind         string                                    `json:"error_kind,omitempty"`
		TransportStage    string                                    `json:"transport_stage"`
		NetworkCause      string                                    `json:"network_cause"`
		ConnectionState   string                                    `json:"connection_state"`
		TransportAttempts []modelgateway.ProviderAttemptObservation `json:"transport_attempts,omitempty"`
		TransportObserved bool                                      `json:"transport_observed"`
		DecisionSHA256    string                                    `json:"decision_sha256,omitempty"`
		Fallback          *ModelRouteFallback                       `json:"fallback,omitempty"`
		ResponseSchema    *modelgateway.ResponseSchemaReceipt       `json:"response_schema,omitempty"`
	}{Version: "model-provider-attempt-audit/v1", Operation: operation, InvocationSHA256: modelRouteHash(key),
		ModelVersionID: selected.ModelVersionID, ModelKey: selected.ModelKey, ProviderID: selected.ProviderID,
		Outcome: outcome, ErrorKind: reason, TransportStage: stage, NetworkCause: cause, ConnectionState: connection,
		TransportAttempts: trace.Snapshot()}
	if len(results) == 1 {
		value.ResponseSchema = results[0].ResponseSchema
		if invokeErr == nil && results[0].Incomplete {
			value.Outcome, value.ErrorKind = "incomplete", results[0].FinishReason
			outcome = value.Outcome
		}
	}
	value.TransportObserved = len(value.TransportAttempts) > 0
	if route != nil {
		value.DecisionSHA256, value.Fallback = route.DecisionSHA256, route.Decision.Fallback
		// The pinned price version is part of the audited routing decision: an
		// attempt's cost attribution must be reconstructible without the route
		// execution state.
		value.PriceVersionID = route.Decision.Price.ID
	}
	body, err := json.Marshal(value)
	if err != nil {
		return
	}
	// Structured logs remain useful if the audit store is unavailable. Both
	// carry allowlisted diagnostics and catalog identities, never raw errors.
	log.Printf("model provider attempt run_id=%q detail=%s", scope.RunID, body)
	if m.modelAttemptRecorder == nil {
		return
	}
	event := audit.Event{ID: "model-attempt-" + modelRouteHash(struct{ Scope, Key, Token string }{modelSelectionScopeHash(scope), key, token}),
		TenantID: scope.TenantID, DepartmentID: scope.DepartmentID, ApplicationID: scope.ApplicationID,
		ActorType: scope.PrincipalType, ActorID: scope.PrincipalID, TraceID: scope.TraceID,
		AggregateType: "run", AggregateID: scope.RunID, Action: "model.provider_attempt", Outcome: outcome,
		Summary: string(body), CreatedAt: finished}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := m.modelAttemptRecorder.Record(writeCtx, event); err != nil {
		log.Printf("model provider attempt audit unavailable run_id=%q invocation_sha256=%s", scope.RunID, value.InvocationSHA256)
	}
}
