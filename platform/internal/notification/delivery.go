package notification

import (
	"errors"
	"time"
)

var ErrDeliveryInProgress = errors.New("notification delivery is already in progress")

// DeliveryClaim is the durable consumer-side idempotency decision. A
// Published Outbox row only says that the event reached the bus; this ledger
// records whether the ChannelAdapter side effect has already completed.
type DeliveryClaim struct {
	Acquired  bool
	Delivered bool
	Attempt   int
}

// DeliveryStore is deliberately separate from EventStore. The same Event.ID
// may be replayed by Kafka after a lost acknowledgement, while producer-side
// Outbox status remains Published. Implementations may be local, SQL, or a
// future remote notification service.
type DeliveryStore interface {
	ClaimDelivery(Event, string, time.Time, time.Duration) (DeliveryClaim, error)
	MarkDeliverySucceeded(string, string) error
	MarkDeliveryFailed(string, string, time.Time, int, error) error
}

type deliveryState struct {
	status   Status
	attempts int
	owner    string
	until    time.Time
}

func (s *Store) ClaimDelivery(event Event, owner string, now time.Time, lease time.Duration) (DeliveryClaim, error) {
	if s == nil || event.ID == "" || owner == "" || lease <= 0 {
		return DeliveryClaim{}, ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliveries == nil {
		s.deliveries = make(map[string]deliveryState)
	}
	state, ok := s.deliveries[event.ID]
	if ok && state.status == Dead {
		return DeliveryClaim{Attempt: state.attempts}, ErrEventDeliveryDeadLetter
	}
	if ok && state.status == Published {
		return DeliveryClaim{Delivered: true, Attempt: state.attempts}, nil
	}
	if ok && state.status == Publishing && state.until.After(now) {
		return DeliveryClaim{}, ErrDeliveryInProgress
	}
	state.status = Publishing
	state.owner = owner
	state.until = now.Add(lease)
	state.attempts++
	s.deliveries[event.ID] = state
	return DeliveryClaim{Acquired: true, Attempt: state.attempts}, nil
}

func (s *Store) MarkDeliverySucceeded(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.deliveries[id]
	if !ok || state.status != Publishing || state.owner != owner {
		return ErrClaimLost
	}
	state.status, state.owner, state.until = Published, "", time.Time{}
	s.deliveries[id] = state
	return nil
}

func (s *Store) MarkDeliveryFailed(id, owner string, now time.Time, maxAttempts int, _ error) error {
	if maxAttempts < 1 {
		return ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.deliveries[id]
	if !ok || state.status != Publishing || state.owner != owner {
		return ErrClaimLost
	}
	if state.attempts >= maxAttempts {
		state.status = Dead
	} else {
		state.status = Failed
		state.until = now.Add(time.Duration(state.attempts) * time.Second)
	}
	state.owner = ""
	s.deliveries[id] = state
	return nil
}

var _ DeliveryStore = (*Store)(nil)
