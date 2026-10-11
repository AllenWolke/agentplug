package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
)

func (m *Module) checkpoint(w http.ResponseWriter, r *http.Request) {
	op, ok := m.authorize(w, r)
	if !ok {
		return
	}
	if m.stateStore == nil {
		m.error(w, 503, "STATE_UNAVAILABLE", "public checkpoint store is not configured", op.Context.TraceID)
		return
	}
	var input struct {
		Operation        string                                `json:"operation"`
		Namespace        string                                `json:"namespace"`
		Key              string                                `json:"key"`
		SchemaID         string                                `json:"schema_id"`
		Revision         uint64                                `json:"revision"`
		ExpectedRevision uint64                                `json:"expected_revision"`
		IdempotencyKey   string                                `json:"idempotency_key"`
		Value            map[string]any                        `json:"value"`
		Reference        *contract.RecoveryCheckpointReference `json:"reference"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || (input.Operation != "load" && input.Operation != "save") {
		m.error(w, 400, "INVALID_REQUEST", "invalid checkpoint operation", op.Context.TraceID)
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || input.Revision > 64 || input.ExpectedRevision >= 64 {
		m.error(w, 400, "INVALID_REQUEST", "invalid checkpoint document or revision", op.Context.TraceID)
		return
	}
	scope := scopeFromHarness(op.Context)
	if input.Reference != nil {
		if input.Operation != "load" || input.Namespace != "" || input.Key != "" || input.SchemaID != "" || input.Revision != 0 || input.ExpectedRevision != 0 || input.IdempotencyKey != "" || input.Value != nil {
			m.error(w, 400, "INVALID_REQUEST", "checkpoint reference cannot be combined with another state operation", op.Context.TraceID)
			return
		}
		reader, ok := m.stateStore.(CheckpointReferenceReader)
		if !ok {
			m.stateError(w, op, ErrStateUnavailable)
			return
		}
		value, err := reader.LoadReference(r.Context(), scope, *input.Reference)
		if err != nil {
			if m.currentCapability(w, r, op) {
				m.stateError(w, op, err)
			}
			return
		}
		m.currentResult(w, r, op, map[string]any{"checkpoint": value, "state_key": input.Reference.StateKey})
		return
	}
	_, stateKey, keyErr := stateKeys(scope, input.Namespace, input.Key)
	if keyErr != nil || !validStateSchema(input.SchemaID) {
		m.error(w, 400, "INVALID_REQUEST", "valid checkpoint namespace, key and schema are required", op.Context.TraceID)
		return
	}
	if input.Operation == "load" {
		value, found, err := m.stateStore.Load(r.Context(), scope, input.Namespace, input.Key, input.SchemaID, input.Revision)
		if err != nil {
			// Even lineage/schema error metadata requires current authority.
			if !m.currentCapability(w, r, op) {
				return
			}
			m.stateError(w, op, err)
			return
		}
		if !found {
			m.currentResult(w, r, op, map[string]any{"checkpoint": nil, "state_key": stateKey})
			return
		}
		m.currentResult(w, r, op, map[string]any{"checkpoint": value, "state_key": stateKey})
		return
	}
	parts := strings.Split(op.Context.PlatformContextToken, ".")
	if len(parts) != 3 {
		m.stateError(w, op, ErrStateDenied)
		return
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		m.stateError(w, op, ErrStateDenied)
		return
	}
	var claims struct {
		Revision  uint64 `json:"execution_revision"`
		TokenHash string `json:"lease_token_hash"`
	}
	if json.Unmarshal(encoded, &claims) != nil || claims.Revision == 0 || len(claims.TokenHash) != 64 {
		m.stateError(w, op, ErrStateDenied)
		return
	}
	ttl := op.Policy.Memory.TaskTTLSeconds
	if ttl <= 0 {
		ttl = op.Policy.Memory.WorkingTTLSeconds
	}
	if ttl > 86400 {
		ttl = 86400
	}
	value, err := m.stateStore.Save(r.Context(), StateWrite{Scope: scope, Lease: sharedkernel.ExecutionLeaseBinding{Revision: claims.Revision, TokenHash: claims.TokenHash}, Namespace: input.Namespace, Key: input.Key, SchemaID: input.SchemaID, IdempotencyKey: input.IdempotencyKey, ExpectedRevision: input.ExpectedRevision, Value: input.Value, TTLSeconds: ttl, MaxEntries: op.Policy.Memory.MaxEntries}, func(ctx context.Context) error { return m.checkCurrentCapability(r.WithContext(ctx), op) })
	if err != nil {
		m.stateError(w, op, err)
		return
	}
	m.currentResult(w, r, op, map[string]any{"checkpoint": value, "state_key": stateKey})
}

func (m *Module) stateError(w http.ResponseWriter, op envelope, err error) {
	switch {
	case errors.Is(err, ErrStateContinuityLost):
		m.error(w, 409, "STATE_CONTINUITY_LOST", "existing checkpoint is expired or unavailable; automatic reinitialization is denied", op.Context.TraceID)
	case errors.Is(err, ErrStateConflict):
		m.error(w, 409, "STATE_REVISION_CONFLICT", "checkpoint revision or operation key conflicts", op.Context.TraceID)
	case errors.Is(err, ErrStateSchema):
		m.error(w, 409, "STATE_SCHEMA_CONFLICT", "checkpoint schema lineage conflicts", op.Context.TraceID)
	case errors.Is(err, ErrStateDenied):
		m.error(w, 403, "STATE_AUTHORITY_DENIED", "current checkpoint authority denied", op.Context.TraceID)
	case errors.Is(err, ErrStateLimit):
		m.error(w, 400, "STATE_LIMIT_EXCEEDED", "checkpoint payload, quota or history limit exceeded", op.Context.TraceID)
	default:
		m.error(w, 503, "STATE_UNAVAILABLE", "checkpoint persistence unavailable", op.Context.TraceID)
	}
}
