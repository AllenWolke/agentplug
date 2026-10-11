package compensation

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lexagent/platform/internal/sqlutil"
)

// Owner-only immutable metadata lookup. An opaque event/reference alone is
// not permission: the caller must prove the event, scope and current authority
// before replay preparation. Ambiguous/malformed historical bindings deny.
func (s *SQLStore) ReadEffectReferenceTx(ctx context.Context, tx *sql.Tx, provider, ref string) (Step, error) {
	if s == nil || ctx == nil || tx == nil || !token(provider, 128) || !token(ref, 255) {
		return Step{}, ErrInvalid
	}
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT step_id,spec_digest,spec_json FROM platform_compensation_step WHERE spec_json->>'provider'=? AND spec_json->>'effect_ref'=? LIMIT 2`), provider, ref)
	if err != nil {
		return Step{}, err
	}
	defer rows.Close()
	var found Step
	count := 0
	for rows.Next() {
		var id, digest string
		var raw []byte
		if err = rows.Scan(&id, &digest, &raw); err != nil {
			return Step{}, err
		}
		if len(raw) > 16384 || json.Unmarshal(raw, &found) != nil || found.Validate() != nil || found.ID != id || found.Digest() != digest || found.Provider != provider || found.Ref != ref {
			return Step{}, ErrConflict
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return Step{}, err
	}
	if count != 1 {
		return Step{}, ErrConflict
	}
	return found, nil
}
