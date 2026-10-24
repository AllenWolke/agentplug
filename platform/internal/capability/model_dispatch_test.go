package capability

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/usagecost"
)

func dispatchFixture(t *testing.T) (*memoryModelInvocationStore, ModelInvocation) {
	t.Helper()
	m := NewModuleWithKnowledgeAndPolicies("internal-token", "signing-secret", nil, "platform", "agent-runtime", nil, governedInvocationResolver())
	s := m.modelStore.(*memoryModelInvocationStore)
	r, _, err := s.ReserveGoverned(context.Background(), "scope", "key", "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	recovery := BillingRecovery{AttemptToken: r.AttemptToken, SendPhase: "prepared", SendDeadline: time.Now().Add(time.Minute),
		Reservation: usagecost.ModelBudgetReservation{ReservationID: "reservation", Scope: usagecost.ModelBudgetScope{TenantID: "tenant"}}}
	if err := s.SaveBillingRecovery(context.Background(), "scope", "key", "fingerprint", nil, 0, recovery); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	r = cloneInvocation(s.records["scope\x00key"])
	s.mu.Unlock()
	return s, r
}

func TestDispatchFenceOnlyOneOwnerCanEnterProvider(t *testing.T) {
	s, r := dispatchFixture(t)
	ctx := context.Background()
	if err := s.BeginModelDispatch(ctx, r.ScopeHash, r.Key, r.Fingerprint, "stale-token"); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("stale attempt entered dispatch", err)
	}
	if err := s.BeginModelDispatch(ctx, r.ScopeHash, r.Key, r.Fingerprint, r.AttemptToken); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginModelDispatch(ctx, r.ScopeHash, r.Key, r.Fingerprint, r.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("dispatch replay authorized another send", err)
	}
	// A stale prepared read cannot release an attempt that already dispatched.
	r.Recovery.SendDeadline = time.Now().Add(-time.Second)
	if _, err := s.PersistExpiredPrepared(ctx, r); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("prepared worker released dispatched attempt", err)
	}
}

func TestExpiredPreparedProofFencesDelayedOwnerAndPersistsExactUnsentReceipt(t *testing.T) {
	s, r := dispatchFixture(t)
	r.Recovery.SendDeadline = time.Now().Add(-time.Second)
	s.mu.Lock()
	s.records["scope\x00key"] = cloneInvocation(r)
	s.mu.Unlock()
	unsent, err := s.PersistExpiredPrepared(context.Background(), r)
	if err != nil || unsent.Recovery.Decision == nil || !unsent.Recovery.Unsent || unsent.Recovery.Decision.Outcome != "no_charge" {
		t.Fatal("no durable prepared-expiry proof", err)
	}
	if err := s.BeginModelDispatch(context.Background(), r.ScopeHash, r.Key, r.Fingerprint, r.AttemptToken); !errors.Is(err, ErrModelInvocationConflict) {
		t.Fatal("delayed owner sent after release proof", err)
	}
	if err := s.FinishUnsent(context.Background(), unsent); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchCancellationBeforeFenceDoesNotConsumeSendRight(t *testing.T) {
	s, r := dispatchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.BeginModelDispatch(ctx, r.ScopeHash, r.Key, r.Fingerprint, r.AttemptToken); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.BeginModelDispatch(context.Background(), r.ScopeHash, r.Key, r.Fingerprint, r.AttemptToken); err != nil {
		t.Fatal("cancelled CAS changed durable phase", err)
	}
}
