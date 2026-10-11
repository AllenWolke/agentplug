package agentplatform

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
)

const maxRecoveryCheckpointReferenceBytes = 4096

var recoveryCheckpointReferenceFields = map[string]struct{}{
	"state_key": {}, "revision": {}, "schema_id": {}, "content_hash": {}, "execution_revision": {}, "expires_at": {},
}

// PrepareContext uses the approved platform prompt/window policy and returns
// a model request transcript. It does not invoke or bill a model.
func (c *CapabilityClient) PrepareContext(ctx context.Context, messages []map[string]any, functionNames []string) (map[string]any, error) {
	return c.Post(ctx, "/internal/context/prepare", map[string]any{"messages": messages, "function_names": functionNames})
}

// LoadCheckpoint retrieves state through the current signed execution, not
// through a database connection. revision=0 selects the current checkpoint.
func (c *CapabilityClient) LoadCheckpoint(ctx context.Context, namespace, key, schemaID string, revision uint64) (map[string]any, error) {
	if revision > 64 {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "checkpoint revision exceeds supported history"}
	}
	return c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "load", "namespace": namespace, "key": key, "schema_id": schemaID, "revision": revision})
}

// LoadRecoveryCheckpoint revalidates one public checkpoint reference through
// the current signed execution. This is a read-only check under current
// authorization, not execution permission or a complete SDK recovery entry.
func (c *CapabilityClient) LoadRecoveryCheckpoint(ctx context.Context, reference map[string]any) (map[string]any, error) {
	snapshot, err := cloneRecoveryCheckpointReference(reference)
	if err != nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "invalid recovery checkpoint reference"}
	}
	return c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "load", "reference": snapshot})
}

func cloneRecoveryCheckpointReference(reference map[string]any) (map[string]any, error) {
	if reference == nil || len(reference) != len(recoveryCheckpointReferenceFields) {
		return nil, ErrInvalidCapability
	}
	for key := range reference {
		if _, ok := recoveryCheckpointReferenceFields[key]; !ok {
			return nil, ErrInvalidCapability
		}
	}
	for key := range recoveryCheckpointReferenceFields {
		if _, ok := reference[key]; !ok {
			return nil, ErrInvalidCapability
		}
	}
	encoded, err := json.Marshal(reference)
	if err != nil || len(encoded) == 0 || len(encoded) > maxRecoveryCheckpointReferenceBytes {
		return nil, ErrInvalidCapability
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var snapshot map[string]any
	if decoder.Decode(&snapshot) != nil || snapshot == nil {
		return nil, ErrInvalidCapability
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, ErrInvalidCapability
	}
	for _, key := range []string{"state_key", "schema_id", "content_hash", "expires_at"} {
		if _, ok := snapshot[key].(string); !ok {
			return nil, ErrInvalidCapability
		}
	}
	revision, ok := snapshot["revision"].(json.Number)
	if !ok {
		return nil, ErrInvalidCapability
	}
	revisionValue, err := strconv.ParseUint(revision.String(), 10, 64)
	if err != nil || revisionValue == 0 || revisionValue > 64 {
		return nil, ErrInvalidCapability
	}
	executionRevision, ok := snapshot["execution_revision"].(json.Number)
	if !ok {
		return nil, ErrInvalidCapability
	}
	executionRevisionValue, err := strconv.ParseUint(executionRevision.String(), 10, 64)
	if err != nil || executionRevisionValue == 0 || executionRevisionValue > (1<<53)-1 {
		return nil, ErrInvalidCapability
	}
	return snapshot, nil
}

// SaveCheckpoint uses explicit CAS and a stable step idempotency key. The
// platform owns TTL/quota, scope, audit and generation fencing. A conflict is
// returned to the caller rather than silently retrying a different revision.
func (c *CapabilityClient) SaveCheckpoint(ctx context.Context, namespace, key, schemaID, idempotencyKey string, expectedRevision uint64, value map[string]any) (map[string]any, error) {
	if expectedRevision >= 64 || idempotencyKey == "" || value == nil {
		return nil, &AppError{Code: "REQUEST_INVALID", Message: "checkpoint CAS, operation key and object are required"}
	}
	return c.Post(ctx, "/internal/state/checkpoint", map[string]any{"operation": "save", "namespace": namespace, "key": key, "schema_id": schemaID, "idempotency_key": idempotencyKey, "expected_revision": expectedRevision, "value": value})
}
