package capability

import (
	"context"
	"github.com/lexagent/platform/internal/sqlutil"
	"strings"
	"time"
)

// Preparation owns a nonce, not just a request fingerprint shared by retries.
// 准备阶段拥有独立尝试令牌，不能仅凭多个重试共有的请求摘要判定执行权。
type ModelPreparationStore interface {
	ReserveGoverned(context.Context, string, string, string) (ModelInvocation, bool, error)
	RecoverExpiredPreparations(context.Context) (int64, error)
	FailPreparation(context.Context, string, string, string, string) error
}

func newPreparation() (string, time.Time, error) {
	id, err := newModelBudgetAttemptID()
	if err != nil {
		return "", time.Time{}, err
	}
	return strings.TrimPrefix(id, "attempt-"), time.Now().UTC().Add(2 * time.Minute), nil
}

func (s *memoryModelInvocationStore) ReserveGoverned(_ context.Context, scope, key, fingerprint string) (ModelInvocation, bool, error) {
	token, until, err := newPreparation()
	if err != nil {
		return ModelInvocation{}, false, err
	}
	return s.reserveModel(scope, key, fingerprint, 0, 0, token, until)
}
func (s *SQLModelInvocationStore) ReserveGoverned(ctx context.Context, scope, key, fingerprint string) (ModelInvocation, bool, error) {
	token, until, err := newPreparation()
	if err != nil {
		return ModelInvocation{}, false, err
	}
	return retryModelReservation(ctx, func() (ModelInvocation, bool, error) {
		return s.reserveModel(ctx, scope, key, fingerprint, 0, 0, token, until)
	})
}

func (s *memoryModelInvocationStore) RecoverExpiredPreparations(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for key, r := range s.records {
		if count >= 16 {
			break
		}
		if r.Status == "running" && r.AttemptToken != "" && r.Recovery == nil && r.Response == nil && !r.PreparationUntil.After(time.Now()) {
			r.Status = "failed"
			r.AttemptToken = ""
			r.PreparationUntil = time.Time{}
			s.records[key] = r
			count++
		}
	}
	return count, nil
}
func (s *SQLModelInvocationStore) RecoverExpiredPreparations(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`WITH expired AS MATERIALIZED (
SELECT scope_hash,idempotency_key FROM platform_model_invocation
WHERE status='running' AND billing_state='preparing' AND invocation_token<>''
AND billing_recovery_json IS NULL AND response_json IS NULL AND preparation_deadline<=clock_timestamp()
ORDER BY preparation_deadline,scope_hash,idempotency_key LIMIT 16 FOR UPDATE SKIP LOCKED
)
UPDATE platform_model_invocation AS invocation
SET status='failed',billing_state='done',invocation_token='',preparation_deadline=NULL,updated_at=clock_timestamp()
FROM expired WHERE invocation.scope_hash=expired.scope_hash AND invocation.idempotency_key=expired.idempotency_key`))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
func (s *memoryModelInvocationStore) FailPreparation(_ context.Context, scope, key, fingerprint, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = scope + "\x00" + key
	r, ok := s.records[key]
	if !ok || r.Status != "running" || r.Fingerprint != fingerprint || r.AttemptToken != token || token == "" || r.Recovery != nil || r.Response != nil {
		return ErrModelInvocationConflict
	}
	r.Status = "failed"
	r.AttemptToken = ""
	r.PreparationUntil = time.Time{}
	s.records[key] = r
	return nil
}
func (s *SQLModelInvocationStore) FailPreparation(ctx context.Context, scope, key, fingerprint, token string) error {
	if token == "" {
		return ErrModelInvocationConflict
	}
	// This transition is available only before a durable send intent exists.
	// "done" closes an unsent preparation; it does not settle provider usage.
	result, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation SET status='failed',billing_state='done',invocation_token='',preparation_deadline=NULL,updated_at=clock_timestamp() WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND invocation_token=? AND status='running' AND billing_state='preparing' AND billing_recovery_json IS NULL AND response_json IS NULL`), scope, key, fingerprint, token)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrModelInvocationConflict
	}
	return nil
}
