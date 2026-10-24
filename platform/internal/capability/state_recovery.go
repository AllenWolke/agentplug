package capability

import (
	"context"
	"database/sql"
	"time"

	"github.com/lexagent/platform/internal/contract"
	"github.com/lexagent/platform/internal/sharedkernel"
	"github.com/lexagent/platform/internal/sqlutil"
)

// CaptureRecoveryCheckpointsTx snapshots bounded, non-secret checkpoint
// metadata while the caller holds the Run row update lock and has confirmed
// that the prior execution generation stopped. It locks heads before payloads
// in stable order and never returns checkpoint business values.
func (s *SQLCheckpointStore) CaptureRecoveryCheckpointsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, stoppedRevision uint64) ([]contract.RecoveryCheckpointReference, error) {
	return s.CaptureRecoveryCheckpointSetTx(ctx, tx, scope, stoppedRevision, contract.MaxRecoveryCheckpoints)
}

// The larger limit is used only by an explicitly approved paged publication.
// Group handoffs and old runtime snapshots keep their original inline limit.
func (s *SQLCheckpointStore) CaptureRecoveryCheckpointSetTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, stoppedRevision uint64, maximum int) ([]contract.RecoveryCheckpointReference, error) {
	if s == nil || s.db == nil || tx == nil || ctx == nil || ctx.Err() != nil || stoppedRevision == 0 || stoppedRevision >= 1<<53 {
		return nil, ErrStateUnavailable
	}
	if maximum != contract.MaxRecoveryCheckpoints && maximum != contract.MaxRecoveryCheckpointSet {
		return nil, ErrStateLimit
	}
	prefix, _, err := stateKeys(scope, "recovery", "snapshot")
	if err != nil {
		return nil, err
	}

	type stateHead struct {
		key      string
		schemaID string
		revision int64
		expires  time.Time
	}
	heads := make([]stateHead, 0, maximum)
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT scope_key,schema_id,revision,expires_at
		FROM platform_business_state_head WHERE scope_prefix=?
		ORDER BY scope_key LIMIT ? FOR SHARE`), prefix, maximum+1)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var head stateHead
		if err := rows.Scan(&head.key, &head.schemaID, &head.revision, &head.expires); err != nil {
			_ = rows.Close()
			return nil, err
		}
		heads = append(heads, head)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(heads) == 0 {
		return nil, ErrStateContinuityLost
	}
	if len(heads) > maximum {
		return nil, ErrStateLimit
	}

	references := make([]contract.RecoveryCheckpointReference, 0, len(heads))
	// Heads are already locked in stable order. Read their current payloads in
	// one statement, preserving the same lock order and integrity checks. An
	// absent payload is detected by comparing every returned key to the heads.
	payloads, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT c.scope_key,c.revision,c.schema_id,c.value_json,c.content_hash,c.execution_revision,c.expires_at
		FROM platform_business_checkpoint c JOIN platform_business_state_head h
		ON c.scope_key=h.scope_key AND c.revision=h.revision
		WHERE h.scope_prefix=? ORDER BY c.scope_key FOR SHARE OF c`), prefix)
	if err != nil {
		return nil, err
	}
	defer payloads.Close()
	for payloads.Next() {
		index := len(references)
		if index >= len(heads) {
			return nil, ErrStateUnavailable
		}
		head := heads[index]
		if head.revision < 1 || head.revision > int64(contract.MaxCheckpointRevisions) || !validStateSchema(head.schemaID) {
			return nil, ErrStateUnavailable
		}
		var revision, executionRevision int64
		var key, schemaID, contentHash string
		var raw []byte
		var expires time.Time
		err := payloads.Scan(&key, &revision, &schemaID, &raw, &contentHash, &executionRevision, &expires)
		if err != nil {
			return nil, err
		}
		if key != head.key {
			return nil, ErrStateContinuityLost
		}
		if revision < 1 || revision > int64(contract.MaxCheckpointRevisions) || uint64(revision) != uint64(head.revision) ||
			schemaID != head.schemaID || !validStateSchema(schemaID) || executionRevision < 1 ||
			uint64(executionRevision) > stoppedRevision || len(raw) > 256<<10 {
			return nil, ErrStateUnavailable
		}
		var value map[string]any
		if err := decodeStateValue(raw, &value); err != nil {
			return nil, ErrStateUnavailable
		}
		hash, err := stateContentHash(schemaID, value)
		if err != nil || hash != contentHash {
			return nil, ErrStateUnavailable
		}
		reference := contract.RecoveryCheckpointReference{
			StateKey:          head.key,
			Revision:          uint64(revision),
			SchemaID:          schemaID,
			ContentHash:       contentHash,
			ExecutionRevision: uint64(executionRevision),
			ExpiresAt:         expires,
		}
		if reference.Validate(stoppedRevision) != nil {
			return nil, ErrStateUnavailable
		}
		references = append(references, reference)
	}
	if err := payloads.Err(); err != nil {
		return nil, err
	}
	if err := payloads.Close(); err != nil {
		return nil, err
	}
	if len(references) != len(heads) {
		return nil, ErrStateContinuityLost
	}

	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	for index, head := range heads {
		if !head.expires.After(now) || !references[index].ExpiresAt.After(now) {
			return nil, ErrStateContinuityLost
		}
	}
	return references, nil
}
