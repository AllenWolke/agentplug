package capability

import (
	"context"
	"encoding/json"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
)

func dispatchIntent(r ModelInvocation, token string) (BillingRecovery, error) {
	if token == "" || r.Status != "reconcile" || r.Recovery == nil ||
		r.Recovery.AttemptToken != token || r.Recovery.SendPhase != "prepared" ||
		r.Recovery.SendDeadline.IsZero() || !r.Recovery.SendDeadline.After(time.Now()) ||
		r.Recovery.Decision != nil || r.Recovery.Event != nil || r.Response != nil {
		return BillingRecovery{}, ErrModelInvocationConflict
	}
	intent := *r.Recovery
	intent.SendPhase = "dispatching"
	return intent, nil
}

func (s *SQLModelInvocationStore) BeginModelDispatch(ctx context.Context, scope, key, fingerprint, token string) error {
	if token == "" {
		return ErrModelInvocationConflict
	}
	// Single atomic CAS competes with prepared-expiry recovery. No connection
	// or row lock is retained while the provider is running. The existing row
	// binds fingerprint/reservation/owner; avoid a preceding network read.
	updated, err := s.db.ExecContext(ctx, sqlutil.Bind(`UPDATE platform_model_invocation
 SET billing_recovery_json=jsonb_set(billing_recovery_json::jsonb,'{send_phase}','"dispatching"'::jsonb)::text,updated_at=clock_timestamp()
 WHERE scope_hash=? AND idempotency_key=? AND fingerprint=? AND invocation_token=?
 AND status='reconcile' AND billing_state='inflight' AND response_json IS NULL
 AND billing_recovery_json::jsonb->>'attempt_token'=?
 AND billing_recovery_json::jsonb->>'send_phase'='prepared'
 AND billing_recovery_json::jsonb->>'event' IS NULL
 AND billing_recovery_json::jsonb->>'decision' IS NULL
 AND (billing_recovery_json::jsonb->>'send_deadline')::timestamptz>clock_timestamp()`),
		scope, key, fingerprint, token, token)
	if err != nil {
		return err
	}
	if n, err := updated.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrModelInvocationConflict
	}
	return nil
}

func (s *memoryModelInvocationStore) BeginModelDispatch(ctx context.Context, scope, key, fingerprint, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[scope+"\x00"+key]
	if !ok || r.Fingerprint != fingerprint || r.AttemptToken != token {
		return ErrModelInvocationConflict
	}
	intent, err := dispatchIntent(r, token)
	if err != nil {
		return err
	}
	r = cloneInvocation(r)
	r.Recovery = &intent
	s.records[scope+"\x00"+key] = r
	return nil
}

func expiredPreparedDecision(r ModelInvocation) (BillingDecision, error) {
	if r.Recovery == nil || r.Recovery.SendPhase != "prepared" || r.Recovery.SendDeadline.IsZero() || r.Recovery.SendDeadline.After(time.Now()) {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	d, err := unsentDecision(r, r.Recovery.AttemptToken)
	if err != nil {
		return d, err
	}
	d.ID = "prepared-" + r.Recovery.AttemptToken
	d.Reason = "durable prepared attempt expired without winning the dispatch fence"
	d.ProviderRef = "system:prepared-expired:" + r.Recovery.Reservation.ReservationID
	if !validBillingDecision(d) {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	return d, nil
}

func (s *SQLModelInvocationStore) PersistExpiredPrepared(ctx context.Context, r ModelInvocation) (ModelInvocation, error) {
	d, err := expiredPreparedDecision(r)
	if err != nil {
		return r, err
	}
	// The exact prepared envelope is rechecked under the decision row lock.
	// A dispatch CAS that won after the worker read makes this release fail.
	err = s.acceptBillingDecision(ctx, r.ScopeHash, r.Key, r.Fingerprint, d, "inflight", r.Recovery.AttemptToken, preparedBillingProof{Recovery: *r.Recovery})
	if err != nil {
		return r, err
	}
	return s.GetBillingRecord(ctx, r.ScopeHash, r.Key)
}

func (s *memoryModelInvocationStore) PersistExpiredPrepared(ctx context.Context, r ModelInvocation) (ModelInvocation, error) {
	if err := ctx.Err(); err != nil {
		return r, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.records[r.ScopeHash+"\x00"+r.Key]
	if !ok || current.Fingerprint != r.Fingerprint {
		return r, ErrModelInvocationConflict
	}
	before, err := json.Marshal(r.Recovery)
	actual, actualErr := json.Marshal(current.Recovery)
	if err != nil || actualErr != nil || string(before) != string(actual) {
		return r, ErrModelInvocationConflict
	}
	d, err := expiredPreparedDecision(current)
	if err != nil {
		return r, err
	}
	current = cloneInvocation(current)
	current.Recovery.Decision, current.Recovery.Unsent = &d, true
	current.Recovery.SendDeadline = time.Time{}
	current.RetryAt = time.Time{}
	s.records[r.ScopeHash+"\x00"+r.Key] = current
	return cloneInvocation(current), nil
}
