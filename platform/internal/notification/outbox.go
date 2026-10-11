package notification

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidEvent = errors.New("invalid notification event")
	ErrConflict     = errors.New("notification event idempotency conflict")
	ErrClaimLost    = errors.New("notification claim lost")
)

type Status string

const (
	Pending    Status = "pending"
	Publishing Status = "publishing"
	Failed     Status = "failed"
	Published  Status = "published"
	Dead       Status = "dead"
)

type Event struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	DepartmentID  string         `json:"department_id"`
	ApplicationID string         `json:"application_id"`
	Topic         string         `json:"topic"`
	EventType     string         `json:"event_type"`
	PartitionKey  string         `json:"partition_key"`
	Payload       map[string]any `json:"payload"`
	Status        Status         `json:"status"`
	Attempts      int            `json:"attempts"`
	NextAttemptAt time.Time      `json:"next_attempt_at"`
	ClaimOwner    string         `json:"claim_owner"`
	ClaimUntil    time.Time      `json:"claim_until"`
}

// EventStore is the storage seam consumed by the dispatcher. The in-memory
// Store remains useful for tests while SQL/Kafka adapters can be swapped in
// without changing notification semantics.
// EventStore 是 Dispatcher 使用的存储边界；内存 Store 用于测试，SQL/Kafka
// Adapter 可在不改变通知语义的情况下替换。
type EventStore interface {
	Enqueue(Event) (Event, error)
	Claim(owner string, limit int, now time.Time, lease time.Duration) ([]Event, error)
	ClaimID(id, owner string, now time.Time, lease time.Duration) (Event, error)
	MarkPublished(id, owner string) error
	MarkFailed(id, owner string, now time.Time, maxAttempts int) error
}

// TxEnqueuer keeps the Outbox writer inside its owning module while sharing
// the caller's transaction. / 跨模块仅调用事务 Port，通知模块拥有 Outbox 写入。
type TxEnqueuer interface {
	EnqueueTx(context.Context, *sql.Tx, Event) (Event, error)
}

func (e Event) Validate() error {
	if err := e.validateFields(); err != nil {
		return ErrInvalidEvent
	}
	// Producers may only enqueue a new/pending event.  Accepting Published or
	// Dead from the wire would let a caller bypass delivery and retry state.
	if e.Status != "" && e.Status != Pending {
		return ErrInvalidEvent
	}
	if e.Attempts < 0 {
		return ErrInvalidEvent
	}
	return nil
}

// ValidateForDelivery validates an event after it has been claimed by the
// outbox worker. Claiming intentionally changes Status to publishing, so
// adapters must not call the producer-only Validate method here.
func (e Event) ValidateForDelivery() error {
	if err := e.validateFields(); err != nil {
		return ErrInvalidEvent
	}
	if e.Status != "" && e.Status != Pending && e.Status != Publishing && e.Status != Failed {
		return ErrInvalidEvent
	}
	if e.Attempts < 0 {
		return ErrInvalidEvent
	}
	return nil
}

func (e Event) validateFields() error {
	if e.ID == "" || e.TenantID == "" || e.DepartmentID == "" || e.ApplicationID == "" || e.Topic == "" || e.EventType == "" || e.PartitionKey == "" || e.Payload == nil {
		return ErrInvalidEvent
	}
	return nil
}

type Store struct {
	mu         sync.Mutex
	events     map[string]Event
	deliveries map[string]deliveryState
}

func NewStore() *Store {
	return &Store{events: make(map[string]Event), deliveries: make(map[string]deliveryState)}
}

func (s *Store) Enqueue(event Event) (Event, error) {
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.events[event.ID]; ok {
		if !sameEventValue(old, event) {
			return Event{}, ErrConflict
		}
		return old, nil
	}
	if event.Status == "" {
		event.Status = Pending
	}
	if event.NextAttemptAt.IsZero() {
		event.NextAttemptAt = time.Now().UTC()
	}
	s.events[event.ID] = event
	return event, nil
}

func sameEventValue(left, right Event) bool {
	if left.TenantID != right.TenantID ||
		left.DepartmentID != right.DepartmentID ||
		left.ApplicationID != right.ApplicationID ||
		left.Topic != right.Topic ||
		left.EventType != right.EventType ||
		left.PartitionKey != right.PartitionKey {
		return false
	}
	leftPayload, leftErr := json.Marshal(left.Payload)
	rightPayload, rightErr := json.Marshal(right.Payload)
	if leftErr != nil || rightErr != nil {
		return false
	}
	var leftValue, rightValue any
	if json.Unmarshal(leftPayload, &leftValue) != nil || json.Unmarshal(rightPayload, &rightValue) != nil {
		return false
	}
	canonicalLeft, leftErr := json.Marshal(leftValue)
	canonicalRight, rightErr := json.Marshal(rightValue)
	return leftErr == nil && rightErr == nil && bytes.Equal(canonicalLeft, canonicalRight)
}

func (s *Store) Claim(owner string, limit int, now time.Time, lease time.Duration) ([]Event, error) {
	if owner == "" || limit <= 0 || lease <= 0 {
		return nil, ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, 0, limit)
	for id, event := range s.events {
		if len(out) >= limit || (event.Status != Pending && event.Status != Failed && !(event.Status == Publishing && !event.ClaimUntil.After(now))) || event.NextAttemptAt.After(now) {
			continue
		}
		event.Status = Publishing
		event.ClaimOwner = owner
		event.ClaimUntil = now.Add(lease)
		s.events[id] = event
		out = append(out, event)
	}
	return out, nil
}

func (s *Store) ClaimID(id, owner string, now time.Time, lease time.Duration) (Event, error) {
	if id == "" || owner == "" || lease <= 0 {
		return Event{}, ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok || event.NextAttemptAt.After(now) || (event.Status != Pending && event.Status != Failed && !(event.Status == Publishing && !event.ClaimUntil.After(now))) {
		return Event{}, ErrClaimLost
	}
	event.Status = Publishing
	event.ClaimOwner = owner
	event.ClaimUntil = now.Add(lease)
	s.events[id] = event
	return event, nil
}

func (s *Store) MarkPublished(id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok || event.Status != Publishing || event.ClaimOwner != owner {
		return ErrClaimLost
	}
	event.Status, event.ClaimOwner = Published, ""
	event.ClaimUntil = time.Time{}
	s.events[id] = event
	return nil
}

func (s *Store) MarkFailed(id, owner string, now time.Time, maxAttempts int) error {
	if maxAttempts < 1 {
		return ErrInvalidEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok || event.Status != Publishing || event.ClaimOwner != owner {
		return ErrClaimLost
	}
	event.Attempts++
	event.ClaimOwner, event.ClaimUntil = "", time.Time{}
	if event.Attempts >= maxAttempts {
		event.Status = Dead
	} else {
		event.Status = Failed
		event.NextAttemptAt = now.Add(time.Duration(event.Attempts) * time.Second)
	}
	s.events[id] = event
	return nil
}
