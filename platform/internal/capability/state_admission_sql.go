package capability

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

const checkpointTransactionBound = 30 * time.Second

// No business value is stored here. A failed data transaction conservatively
// keeps its resource admission; reads/recovery still see only committed State.
func (s *SQLCheckpointStore) reserveCheckpointQuota(ctx context.Context, write StateWrite, prefix, id string, check func(context.Context) error) error {
	// Reuse only this exact resource slot, with enough TTL coverage for the
	// following data transaction. This is not an authority cache: Save still
	// takes the IAM/Run/lease fences and checks current capability before any
	// State read/write and again before commit. No resource expiry is extended
	// on this path, so concurrent admissions continue to count this same slot.
	// Keep the current quota count: a smaller published limit cannot reuse an
	// older, more permissive allocation. Only the exclusive mutex/upsert and
	// redundant resource-transaction authority work are avoided.
	var reusable bool
	finishReuse := capabilityPhase(ctx, "state.quota_reuse")
	err := s.db.QueryRowContext(ctx, sqlutil.Bind(`SELECT EXISTS (
 SELECT 1 FROM platform_business_state_admission r
 WHERE r.scope_key=? AND r.scope_prefix=?
 AND r.expires_at >= clock_timestamp() + (? * interval '1 second')
 AND (SELECT count(*) FROM (
   SELECT scope_key FROM platform_business_state_head WHERE scope_prefix=? AND expires_at>clock_timestamp()
   UNION SELECT scope_key FROM platform_business_state_admission WHERE scope_prefix=? AND expires_at>clock_timestamp()
 ) admitted WHERE scope_key<>?) < ?
)`), id, prefix, write.TTLSeconds+int(checkpointTransactionBound/time.Second)/2,
		prefix, prefix, id, write.MaxEntries).Scan(&reusable)
	finishReuse()
	if err != nil {
		return err
	}
	if reusable {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ctx = sqlutil.WithContinuityTransaction(ctx, s.db, tx)
	if err = s.guard(ctx, tx, write.Scope, write.Lease); err != nil {
		return errors.Join(ErrStateDenied, err)
	}
	// Fresh authority is checked under the same IAM/Run fences, before the
	// scope quota mutex. No provider/effect runs in this resource transaction.
	if err = check(ctx); err != nil {
		return errors.Join(ErrStateDenied, err)
	}
	if err = lockLedgerScope(ctx, tx, "business-state", prefix); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return err
	}
	var others int
	if err = tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM (
 SELECT scope_key FROM platform_business_state_head WHERE scope_prefix=? AND expires_at>?
 UNION SELECT scope_key FROM platform_business_state_admission WHERE scope_prefix=? AND expires_at>?
 ) admitted WHERE scope_key<>?`), prefix, now, prefix, now, id).Scan(&others); err != nil {
		return err
	}
	if others >= write.MaxEntries {
		return ErrStateLimit
	}
	expires := now.Add(time.Duration(write.TTLSeconds)*time.Second + checkpointTransactionBound)
	_, err = tx.ExecContext(ctx, sqlutil.Bind(`INSERT INTO platform_business_state_admission(scope_key,scope_prefix,expires_at,updated_at)
 VALUES(?,?,?,?) ON CONFLICT(scope_key) DO UPDATE SET expires_at=GREATEST(platform_business_state_admission.expires_at,EXCLUDED.expires_at),updated_at=EXCLUDED.updated_at`), id, prefix, expires, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLCheckpointStore) checkpointQuotaExpiry(ctx context.Context, tx *sql.Tx, prefix, id string) (time.Time, error) {
	var expiry, now time.Time
	err := tx.QueryRowContext(ctx, sqlutil.Bind(`SELECT expires_at,clock_timestamp() FROM platform_business_state_admission WHERE scope_key=? AND scope_prefix=?`), id, prefix).Scan(&expiry, &now)
	if err != nil {
		return time.Time{}, err
	}
	if !expiry.After(now) {
		return time.Time{}, ErrStateLimit
	}
	return expiry, nil
}
