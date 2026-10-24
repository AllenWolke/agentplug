package capability

import (
	"context"
	"encoding/json"
	"time"
)

func unsentDecision(r ModelInvocation, token string) (BillingDecision, error) {
	if token == "" || r.Recovery == nil || r.Recovery.AttemptToken != token || r.Status != "reconcile" || r.Response != nil || r.Recovery.Event != nil {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	if !r.Recovery.AdmissionUntil.IsZero() && (r.Recovery.AdmissionUntil.After(time.Now()) || !r.Recovery.SendDeadline.IsZero()) {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	d := BillingDecision{ID: "unsent-" + token, ActorID: "system:model-gateway", ActorTenant: r.Recovery.Reservation.Scope.TenantID, ReservationID: r.Recovery.Reservation.ReservationID, Outcome: "no_charge", Reason: "adapter confirmed failure before generation request send", ProviderRef: "system:adapter-confirmed-not-sent:" + r.Recovery.Reservation.ReservationID}
	if !validBillingDecision(d) {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	return d, nil
}

// System-only proof path: not exposed by the browser or human decision API.
// 系统未发送证据路径，不向浏览器或人工决策接口暴露。
func (s *SQLModelInvocationStore) PersistUnsent(ctx context.Context, scope, key, fingerprint, token string) (ModelInvocation, error) {
	r, err := s.GetBillingRecord(ctx, scope, key)
	if err != nil {
		return r, err
	}
	if r.Fingerprint != fingerprint {
		return r, ErrModelInvocationConflict
	}
	d, err := unsentDecision(r, token)
	if err != nil {
		return r, err
	}
	expectedState := "inflight"
	if !r.Recovery.AdmissionUntil.IsZero() {
		expectedState = "admitted"
	} else if r.Recovery.SendDeadline.IsZero() {
		// Expiry may have promoted this exact attempt to manual while its
		// owner paused before persisting an adapter's positive no-send proof.
		// A late trusted proof can close it; expiry alone still cannot.
		expectedState = "manual"
	}
	if err := s.acceptBillingDecision(ctx, scope, key, fingerprint, d, expectedState, token); err != nil {
		return r, err
	}
	return s.GetBillingRecord(ctx, scope, key)
}
func (s *SQLModelInvocationStore) FinishUnsent(ctx context.Context, r ModelInvocation) error {
	return s.FinishBillingDecision(ctx, r)
}

func (s *memoryModelInvocationStore) PersistUnsent(_ context.Context, scope, key, fingerprint, token string) (ModelInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := scope + "\x00" + key
	r, ok := s.records[compound]
	if !ok || r.Fingerprint != fingerprint {
		return r, ErrModelInvocationConflict
	}
	d, err := unsentDecision(r, token)
	if err != nil {
		return r, err
	}
	r = cloneInvocation(r)
	if r.Recovery.Decision != nil {
		actual, _ := json.Marshal(r.Recovery.Decision)
		expected, _ := json.Marshal(d)
		if string(actual) != string(expected) {
			return r, ErrModelInvocationConflict
		}
		return r, nil
	}
	r.Recovery.Decision = &d
	r.Recovery.Unsent = true
	r.Recovery.AdmissionUntil = time.Time{}
	r.Recovery.SendDeadline = time.Time{}
	r.RetryAt = time.Time{}
	s.records[compound] = r
	return cloneInvocation(r), nil
}
func (s *memoryModelInvocationStore) FinishUnsent(_ context.Context, r ModelInvocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	compound := r.ScopeHash + "\x00" + r.Key
	current, ok := s.records[compound]
	if !ok || current.Fingerprint != r.Fingerprint || current.AttemptToken != r.AttemptToken || current.Recovery == nil || current.Recovery.Decision == nil || current.Recovery.Decision.Outcome != "no_charge" {
		return ErrModelInvocationConflict
	}
	actual, _ := json.Marshal(current.Recovery)
	expected, _ := json.Marshal(r.Recovery)
	if string(actual) != string(expected) {
		return ErrModelInvocationConflict
	}
	if current.Status == "failed" {
		return nil
	}
	if current.Status != "reconcile" {
		return ErrModelInvocationConflict
	}
	current.Status = "failed"
	s.records[compound] = current
	return nil
}
