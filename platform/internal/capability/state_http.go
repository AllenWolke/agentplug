package capability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
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
		Operation        string                                   `json:"operation"`
		Namespace        string                                   `json:"namespace"`
		Key              string                                   `json:"key"`
		SchemaID         string                                   `json:"schema_id"`
		Revision         uint64                                   `json:"revision"`
		ExpectedRevision uint64                                   `json:"expected_revision"`
		IdempotencyKey   string                                   `json:"idempotency_key"`
		Value            map[string]any                           `json:"value"`
		Reference        *contract.RecoveryCheckpointReference    `json:"reference"`
		ReferenceSet     *contract.RecoveryCheckpointSetReference `json:"reference_set"`
		Offset           int                                      `json:"offset"`
		Limit            int                                      `json:"limit"`
	}
	decoder := json.NewDecoder(bytes.NewReader(op.Input))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || (input.Operation != "load" && input.Operation != "save") {
		m.error(w, 400, "INVALID_REQUEST", "invalid checkpoint operation", op.Context.TraceID)
		return
	}
	var trailing any
	if op.Policy.Memory.ValidateCheckpointHistory() != nil || op.Policy.Memory.ValidateCheckpointAdmission() != nil {
		m.stateError(w, op, ErrStateUnavailable)
		return
	}
	revisionLimit := op.Policy.Memory.CheckpointRevisionLimit()
	if decoder.Decode(&trailing) != io.EOF || input.Revision > revisionLimit || input.ExpectedRevision >= revisionLimit {
		m.error(w, 400, "INVALID_REQUEST", "invalid checkpoint document or revision", op.Context.TraceID)
		return
	}
	scope := scopeFromHarness(op.Context)
	if input.ReferenceSet != nil {
		if input.Operation != "load" || input.Reference != nil || input.Namespace != "" || input.Key != "" || input.SchemaID != "" || input.Revision != 0 || input.ExpectedRevision != 0 || input.IdempotencyKey != "" || input.Value != nil || m.recoveryPager == nil {
			m.stateError(w, op, ErrStateDenied)
			return
		}
		parts := strings.Split(op.Context.PlatformContextToken, ".")
		if len(parts) != 3 {
			m.stateError(w, op, ErrStateDenied)
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Revision  uint64 `json:"execution_revision"`
			TokenHash string `json:"lease_token_hash"`
		}
		if err != nil || json.Unmarshal(raw, &claims) != nil || claims.Revision == 0 || len(claims.TokenHash) != 64 {
			m.stateError(w, op, ErrStateDenied)
			return
		}
		page, err := m.recoveryPager.ReadRecoveryCheckpointPage(r.Context(), scope,
			sharedkernel.ExecutionLeaseBinding{Revision: claims.Revision, TokenHash: claims.TokenHash}, *input.ReferenceSet, input.Offset, input.Limit)
		if err != nil {
			m.stateError(w, op, ErrStateDenied)
			return
		}
		m.currentResult(w, r, op, page)
		return
	}
	if input.Offset != 0 || input.Limit != 0 {
		m.stateError(w, op, ErrStateDenied)
		return
	}
	if input.Reference != nil {
		if input.Reference.Revision > revisionLimit {
			m.stateError(w, op, ErrStateDenied)
			return
		}
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
		m.checkpointResult(w, r, op, map[string]any{"checkpoint": value, "state_key": input.Reference.StateKey})
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
			m.checkpointResult(w, r, op, map[string]any{"checkpoint": nil, "state_key": stateKey})
			return
		}
		if value.Revision > revisionLimit {
			if m.currentCapability(w, r, op) {
				m.stateError(w, op, ErrStateLimit)
			}
			return
		}
		m.checkpointResult(w, r, op, map[string]any{"checkpoint": value, "state_key": stateKey})
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
	value, err := m.stateStore.Save(r.Context(), StateWrite{Scope: scope, Lease: sharedkernel.ExecutionLeaseBinding{Revision: claims.Revision, TokenHash: claims.TokenHash}, Namespace: input.Namespace, Key: input.Key, SchemaID: input.SchemaID, IdempotencyKey: input.IdempotencyKey, ExpectedRevision: input.ExpectedRevision, Value: input.Value, TTLSeconds: ttl, MaxEntries: op.Policy.Memory.MaxEntries, MaxRevisions: revisionLimit, ReservedQuota: op.Policy.Memory.ReservedCheckpointQuota()}, func(ctx context.Context) error { return m.checkCurrentCapability(r.WithContext(ctx), op) })
	if err != nil {
		m.stateError(w, op, err)
		return
	}
	m.checkpointResult(w, r, op, map[string]any{"checkpoint": value, "state_key": stateKey})
}

// Negotiate capacity from the pinned published policy, never business input.
// Legacy response shapes remain unchanged when the optional policy is absent.
func (m *Module) checkpointResult(w http.ResponseWriter, r *http.Request, op envelope, result map[string]any) {
	if op.Policy.Memory.CheckpointHistory != nil {
		result["checkpoint_history"] = op.Policy.Memory.CheckpointHistory
	}
	m.currentResult(w, r, op, result)
}

func (m *Module) stateError(w http.ResponseWriter, op envelope, err error) {
	switch {
	case budgetAdmissionDeferred(err):
		// A failed read/lock check can be wrapped by ErrStateDenied. Preserve
		// its unfinished status so one item cannot masquerade as revoked IAM.
		log.Printf("checkpoint current check unfinished run_id=%q stage=%s reason=%s", op.Context.TaskID, capabilityFailureDiagnostic(err), budgetAdmissionErrorType(err))
		m.error(w, 503, "STATE_UNAVAILABLE", "checkpoint check unfinished; reconcile the original checkpoint operation", op.Context.TraceID)
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
