package capability

import (
	"context"
	"database/sql"
	"time"

	"github.com/lexagent/platform/internal/policyasset"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// LockCheckpointTx holds the selected lineage and payload through a caller's
// control-plane commit. IAM and Run fences must be acquired before this port.
// It never changes state or makes an expired checkpoint readable.
func (s *SQLCheckpointStore) LockCheckpointTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, namespace, key string, expected Checkpoint, requireHead bool) error {
	if s == nil || tx == nil || expected.Revision == 0 || expected.Revision > policyasset.MaximumCheckpointRevisions || expected.ExecutionRevision == 0 || !validStateSchema(expected.SchemaID) {
		return ErrStateDenied
	}
	_, id, err := stateKeys(scope, namespace, key)
	if err != nil {
		return err
	}
	var headRevision uint64
	var headSchema string
	var headExpiry time.Time
	// Explicit head-before-payload locks match the state writer's lineage order.
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,schema_id,expires_at FROM platform_business_state_head WHERE scope_key=? FOR SHARE`), id).Scan(&headRevision, &headSchema, &headExpiry); err != nil {
		return ErrStateUnavailable
	}
	if headSchema != expected.SchemaID || (requireHead && headRevision != expected.Revision) || headRevision < expected.Revision {
		return ErrStateConflict
	}
	var actual Checkpoint
	var raw []byte
	if err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,schema_id,value_json,content_hash,execution_revision,expires_at FROM platform_business_checkpoint WHERE scope_key=? AND revision=? FOR SHARE`), id, expected.Revision).Scan(&actual.Revision, &actual.SchemaID, &raw, &actual.ContentHash, &actual.ExecutionRevision, &actual.ExpiresAt); err != nil {
		return ErrStateUnavailable
	}
	if actual.SchemaID != expected.SchemaID || actual.ContentHash != expected.ContentHash || actual.ExecutionRevision != expected.ExecutionRevision || len(raw) > 256<<10 || decodeStateValue(raw, &actual.Value) != nil {
		return ErrStateConflict
	}
	hash, err := stateContentHash(actual.SchemaID, actual.Value)
	if err != nil || hash != actual.ContentHash {
		return ErrStateUnavailable
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil || !headExpiry.After(now) || !actual.ExpiresAt.After(now) || ctx.Err() != nil {
		return ErrStateDenied
	}
	return nil
}
