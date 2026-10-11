package capability

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// LoadReference cannot select a foreign Run using its state hash or retrieve
// an older payload after the head advanced. It never updates or renews state.
func (s *SQLCheckpointStore) LoadReference(ctx context.Context, scope sharedkernel.Scope, reference contract.RecoveryCheckpointReference) (Checkpoint, error) {
	if s == nil || s.db == nil || reference.ExecutionRevision >= 1<<53 || reference.Validate(reference.ExecutionRevision) != nil {
		return Checkpoint{}, ErrStateDenied
	}
	prefix, _, err := stateKeys(scope, "recovery", "snapshot")
	if err != nil {
		return Checkpoint{}, err
	}
	var checkpoint Checkpoint
	var raw []byte
	var headRevision uint64
	var headSchema string
	var headExpiry, now time.Time
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT h.revision,h.schema_id,h.expires_at,clock_timestamp(),
 c.revision,c.schema_id,c.value_json,c.content_hash,c.execution_revision,c.expires_at
 FROM platform_business_state_head h JOIN platform_business_checkpoint c
 ON c.scope_key=h.scope_key AND c.revision=?
 WHERE h.scope_key=? AND h.scope_prefix=?`), reference.Revision, reference.StateKey, prefix).Scan(
		&headRevision, &headSchema, &headExpiry, &now, &checkpoint.Revision, &checkpoint.SchemaID,
		&raw, &checkpoint.ContentHash, &checkpoint.ExecutionRevision, &checkpoint.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, ErrStateContinuityLost
	}
	if err != nil {
		return Checkpoint{}, err
	}
	if !headExpiry.After(now) || !checkpoint.ExpiresAt.After(now) || !reference.ExpiresAt.After(now) {
		return Checkpoint{}, ErrStateContinuityLost
	}
	if headRevision != reference.Revision || checkpoint.Revision != reference.Revision ||
		headSchema != reference.SchemaID || checkpoint.SchemaID != reference.SchemaID ||
		checkpoint.ContentHash != reference.ContentHash || checkpoint.ExecutionRevision != reference.ExecutionRevision ||
		!checkpoint.ExpiresAt.Equal(reference.ExpiresAt) {
		return Checkpoint{}, ErrStateConflict
	}
	if len(raw) > 256<<10 || decodeStateValue(raw, &checkpoint.Value) != nil {
		return Checkpoint{}, ErrStateUnavailable
	}
	hash, err := stateContentHash(checkpoint.SchemaID, checkpoint.Value)
	if err != nil || hash != checkpoint.ContentHash {
		return Checkpoint{}, ErrStateUnavailable
	}
	return checkpoint, nil
}

// LoadRenewalReference re-reads the exact recovery checkpoint captured for a
// live generation while allowing the public State head to advance afterward.
// The captured payload, schema, hash, execution revision and expiry remain
// immutable; only headRevision >= reference.Revision is allowed here. Dispatch
// and public checkpoint reads must continue to use LoadReference.
func (s *SQLCheckpointStore) LoadRenewalReference(ctx context.Context, scope sharedkernel.Scope, reference contract.RecoveryCheckpointReference) (Checkpoint, error) {
	if s == nil || s.db == nil || ctx == nil || ctx.Err() != nil || reference.ExecutionRevision >= 1<<53 || reference.Validate(reference.ExecutionRevision) != nil {
		return Checkpoint{}, ErrStateDenied
	}
	prefix, _, err := stateKeys(scope, "recovery", "snapshot")
	if err != nil {
		return Checkpoint{}, err
	}
	var checkpoint Checkpoint
	var raw []byte
	var headRevision uint64
	var headSchema string
	var headExpiry, now time.Time
	err = s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT h.revision,h.schema_id,h.expires_at,clock_timestamp(),
 c.revision,c.schema_id,c.value_json,c.content_hash,c.execution_revision,c.expires_at
 FROM platform_business_state_head h JOIN platform_business_checkpoint c
 ON c.scope_key=h.scope_key AND c.revision=?
 WHERE h.scope_key=? AND h.scope_prefix=?`), reference.Revision, reference.StateKey, prefix).Scan(
		&headRevision, &headSchema, &headExpiry, &now, &checkpoint.Revision, &checkpoint.SchemaID,
		&raw, &checkpoint.ContentHash, &checkpoint.ExecutionRevision, &checkpoint.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, ErrStateContinuityLost
	}
	if err != nil {
		return Checkpoint{}, err
	}
	if !headExpiry.After(now) || !checkpoint.ExpiresAt.After(now) || !reference.ExpiresAt.After(now) {
		return Checkpoint{}, ErrStateContinuityLost
	}
	if headRevision < reference.Revision || checkpoint.Revision != reference.Revision || headSchema != reference.SchemaID ||
		checkpoint.SchemaID != reference.SchemaID || checkpoint.ContentHash != reference.ContentHash ||
		checkpoint.ExecutionRevision != reference.ExecutionRevision || !checkpoint.ExpiresAt.Equal(reference.ExpiresAt) {
		return Checkpoint{}, ErrStateConflict
	}
	if len(raw) > 256<<10 || decodeStateValue(raw, &checkpoint.Value) != nil {
		return Checkpoint{}, ErrStateUnavailable
	}
	hash, err := stateContentHash(checkpoint.SchemaID, checkpoint.Value)
	if err != nil || hash != checkpoint.ContentHash {
		return Checkpoint{}, ErrStateUnavailable
	}
	return checkpoint, nil
}
