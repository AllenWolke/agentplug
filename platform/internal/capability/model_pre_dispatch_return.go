package capability

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/lexagent/platform/internal/usagecost"
)

// Optional internal port. Only the owning handler may call this while returning
// before it has even attempted the dispatch CAS. A read or expiry is no proof
// of owner termination. The record CAS also rejects a concurrent dispatch win.
type modelPreDispatchReturnStore interface {
	PersistPreDispatchReturn(context.Context, string, string, string, string) (ModelInvocation, error)
}

func returnedBeforeDispatchDecision(r ModelInvocation, token string) (BillingDecision, error) {
	if r.Recovery == nil || r.Recovery.Decision != nil || r.Recovery.Event != nil ||
		r.Response != nil || r.Status != "reconcile" || token == "" || r.Recovery.AttemptToken != token {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	admitted := !r.Recovery.AdmissionUntil.IsZero() && r.Recovery.SendDeadline.IsZero() && r.Recovery.SendPhase == ""
	prepared := r.Recovery.AdmissionUntil.IsZero() && r.Recovery.SendPhase == "prepared" && !r.Recovery.SendDeadline.IsZero()
	if !admitted && !prepared {
		return BillingDecision{}, ErrModelInvocationConflict
	}
	copy := cloneInvocation(r)
	copy.Recovery.AdmissionUntil = time.Time{}
	d, err := unsentDecision(copy, token)
	if err != nil {
		return d, err
	}
	d = ownerReturnedDecision(d, token, r.Recovery.Reservation.ReservationID)
	if !validBillingDecision(d) {
		return d, ErrModelInvocationConflict
	}
	return d, nil
}

func ownerReturnedDecision(d BillingDecision, token, reservation string) BillingDecision {
	d.ID = "returned-" + token
	d.Reason = "owning handler returned before attempting the dispatch fence"
	d.ProviderRef = "system:owner-returned-before-dispatch:" + reservation
	return d
}

// Route recovery must recognize the exact system proof written by cleanup,
// rather than treat its different decision identity as a provider unknown.
func recordedSystemUnsentProof(record ModelInvocation) bool {
	if record.Status != "failed" || record.Recovery == nil || !record.Recovery.Unsent || record.Recovery.Decision == nil {
		return false
	}
	copy := cloneInvocation(record)
	copy.Status = "reconcile"
	expected, err := unsentDecision(copy, record.Recovery.AttemptToken)
	if err != nil {
		return false
	}
	if record.Recovery.Decision.ID == "returned-"+record.Recovery.AttemptToken {
		if record.Recovery.SendPhase != "" && record.Recovery.SendPhase != "prepared" {
			return false
		}
		expected = ownerReturnedDecision(expected, record.Recovery.AttemptToken, record.Recovery.Reservation.ReservationID)
	}
	return modelRouteHash(expected) == modelRouteHash(*record.Recovery.Decision)
}

func (s *SQLModelInvocationStore) PersistPreDispatchReturn(ctx context.Context, scope, key, fingerprint, token string) (ModelInvocation, error) {
	r, err := s.GetBillingRecord(ctx, scope, key)
	if err != nil {
		return r, err
	}
	if r.Fingerprint != fingerprint {
		return r, ErrModelInvocationConflict
	}
	d, err := returnedBeforeDispatchDecision(r, token)
	if err != nil {
		return r, err
	}
	state := "inflight"
	if !r.Recovery.AdmissionUntil.IsZero() {
		state = "admitted"
	}
	err = s.acceptBillingDecision(ctx, scope, key, fingerprint, d, state, token,
		preparedBillingProof{Recovery: *r.Recovery, OwnerReturned: true})
	if err != nil {
		return r, err
	}
	return s.GetBillingRecord(ctx, scope, key)
}

func (s *memoryModelInvocationStore) PersistPreDispatchReturn(ctx context.Context, scope, key, fingerprint, token string) (ModelInvocation, error) {
	if err := ctx.Err(); err != nil {
		return ModelInvocation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[scope+"\x00"+key]
	if !ok || r.Fingerprint != fingerprint {
		return r, ErrModelInvocationConflict
	}
	d, err := returnedBeforeDispatchDecision(r, token)
	if err != nil {
		return r, err
	}
	r = cloneInvocation(r)
	r.Recovery.Decision, r.Recovery.Unsent = &d, true
	r.Recovery.AdmissionUntil, r.Recovery.SendDeadline = time.Time{}, time.Time{}
	r.RetryAt = time.Time{}
	s.records[scope+"\x00"+key] = r
	return cloneInvocation(r), nil
}

func (m *Module) closePreDispatchReturn(ctx context.Context, scope, key, fingerprint, token, trace string) {
	store, ok := m.modelStore.(modelPreDispatchReturnStore)
	if !ok || token == "" {
		return // Legacy adapters retain their existing bounded recovery.
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	record, err := store.PersistPreDispatchReturn(cleanup, scope, key, fingerprint, token)
	if errors.Is(err, ErrModelInvocationConflict) {
		return // Already closed, not admitted, stale owner, or dispatch won.
	}
	if err == nil {
		release, releaseOK := m.modelBudgets.(usagecost.ModelBudgetManualReleaseStore)
		hold, holdOK := m.modelBudgets.(usagecost.ModelBudgetReconciliationStore)
		lifecycle, finishOK := m.modelStore.(ModelSendLifecycleStore)
		if !releaseOK || !holdOK || !finishOK || record.Recovery == nil || record.Recovery.Decision == nil {
			err = errors.New("pre-dispatch return closure unavailable")
		} else {
			// Admission may precede the pending -> reconciliation transition.
			err = hold.MarkReconciliationNeeded(cleanup, record.Recovery.Reservation)
			if err == nil || errors.Is(err, usagecost.ErrBudgetReservationClosed) {
				err = release.ResolveUncharged(cleanup, record.Recovery.Reservation, record.Recovery.Decision.ProviderRef)
			}
			if err == nil {
				err = lifecycle.FinishUnsent(cleanup, record)
			}
		}
	}
	result := "closed"
	if err != nil {
		result = "retained_for_original_recovery"
	}
	log.Printf("model pre-dispatch owner returned trace=%q outcome=%s", trace, result)
}
