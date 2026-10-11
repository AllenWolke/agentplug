package identity

import (
	"context"
	"errors"
	"github.com/lexagent/platform/internal/sqlutil"
)

// PurgeExpiredRefreshSessions removes only absolutely expired families, never
// the replay evidence of a still-valid family. A bounded batch limits lock time.
func (s *SQLStore) PurgeExpiredRefreshSessions(ctx context.Context, limit int) (int, error) {
	if s == nil || s.db == nil || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid refresh cleanup configuration")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT id FROM platform_identity_refresh_family WHERE expires_at<=? ORDER BY expires_at,id LIMIT ? FOR UPDATE SKIP LOCKED`), s.clock().UTC(), limit)
	if err != nil {
		return 0, err
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil {
		return 0, rowErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_refresh_token WHERE family_id=?`), id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_refresh_oidc_binding WHERE family_id=?`), id); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_refresh_family WHERE id=?`), id); err != nil {
			return 0, err
		}
	}
	proofRows, err := tx.QueryContext(ctx, sqlutil.Bind(`SELECT token_hash FROM platform_identity_step_up WHERE expires_at<=? ORDER BY expires_at,token_hash LIMIT ? FOR UPDATE SKIP LOCKED`), s.clock().UTC(), limit)
	if err != nil {
		return 0, err
	}
	proofs := []string{}
	for proofRows.Next() {
		var hash string
		if err := proofRows.Scan(&hash); err != nil {
			proofRows.Close()
			return 0, err
		}
		proofs = append(proofs, hash)
	}
	proofReadErr, proofCloseErr := proofRows.Err(), proofRows.Close()
	if proofReadErr != nil {
		return 0, proofReadErr
	}
	if proofCloseErr != nil {
		return 0, proofCloseErr
	}
	for _, hash := range proofs {
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_oidc_step_up_proof WHERE token_hash=?`), hash); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_step_up WHERE token_hash=?`), hash); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, sqlutil.Bind(`DELETE FROM platform_identity_oidc_step_up_challenge WHERE token_hash IN (SELECT token_hash FROM platform_identity_oidc_step_up_challenge WHERE expires_at<=? ORDER BY expires_at,token_hash LIMIT ? FOR UPDATE SKIP LOCKED)`), s.clock().UTC(), limit); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

type RefreshSessionJanitor interface {
	PurgeExpiredRefreshSessions(context.Context, int) (int, error)
}
