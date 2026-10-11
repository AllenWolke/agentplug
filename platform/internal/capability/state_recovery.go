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

// CaptureRecoveryCheckpointsTx snapshots bounded, non-secret checkpoint
// metadata while the caller holds the Run row update lock and has confirmed
// that the prior execution generation stopped. It locks heads before payloads
// in stable order and never returns checkpoint business values.
func (s *SQLCheckpointStore) CaptureRecoveryCheckpointsTx(ctx context.Context, tx *sql.Tx, scope sharedkernel.Scope, stoppedRevision uint64) ([]contract.RecoveryCheckpointReference, error) {
	if s == nil || s.db == nil || tx == nil || ctx == nil || ctx.Err() != nil || stoppedRevision == 0 || stoppedRevision >= 1<<53 {
		return nil, ErrStateUnavailable
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
	heads := make([]stateHead, 0, contract.MaxRecoveryCheckpoints)
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT scope_key,schema_id,revision,expires_at
		FROM platform_business_state_head WHERE scope_prefix=?
		ORDER BY scope_key LIMIT ? FOR SHARE`), prefix, contract.MaxRecoveryCheckpoints+1)
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
	if len(heads) > contract.MaxRecoveryCheckpoints {
		return nil, ErrStateLimit
	}

	references := make([]contract.RecoveryCheckpointReference, 0, len(heads))
	for _, head := range heads {
		if head.revision < 1 || head.revision > 64 || !validStateSchema(head.schemaID) {
			return nil, ErrStateUnavailable
		}
		var revision, executionRevision int64
		var schemaID, contentHash string
		var raw []byte
		var expires time.Time
		err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT revision,schema_id,value_json,content_hash,execution_revision,expires_at
			FROM platform_business_checkpoint WHERE scope_key=? AND revision=? FOR SHARE`), head.key, head.revision).Scan(
			&revision, &schemaID, &raw, &contentHash, &executionRevision, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrStateContinuityLost
		}
		if err != nil {
			return nil, err
		}
		if revision < 1 || revision > 64 || uint64(revision) != uint64(head.revision) ||
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
