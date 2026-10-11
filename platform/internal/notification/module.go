package notification

// HTTP boundary for the platform-owned outbox. Kafka consumers and channel
// adapters stay behind the Dispatcher/ChannelAdapter ports.
// 平台 Outbox 的 HTTP 边界；Kafka Consumer 与通道 Adapter 保持在端口后。

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lexagent/platform/internal/bootstrap"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type Module struct {
	store           EventStore
	adapter         ChannelAdapter
	publisher       EventPublisher
	consumer        EventConsumer
	consumerDest    ChannelAdapter
	eventBusClose   io.Closer
	consumerOwner   string
	internalToken   string
	workerCancel    context.CancelFunc
	workerDone      chan struct{}
	consumerDone    chan struct{}
	lifecycleMu     sync.Mutex
	started         bool
	closed          bool
	errorMu         sync.RWMutex
	workerErr       error
	consumerErr     error
	deadLetters     *SQLDeadLetterStore
	deadLetterActor func(*http.Request) (sharedkernel.Scope, error)
	inbox           *SQLInboxChannel
	inboxActor      func(*http.Request) (sharedkernel.Scope, error)
	inboxAuthorize  func(context.Context, *sql.Tx, sharedkernel.Scope) error
}

var (
	ErrModuleStarted = errors.New("notification module already started")
	ErrModuleClosed  = errors.New("notification module is closed")
)

func NewModule(store EventStore, adapter ChannelAdapter, internalToken string) *Module {
	return &Module{store: store, adapter: adapter, internalToken: strings.TrimSpace(internalToken), consumerOwner: fmt.Sprintf("platform-notification-consumer-%d", time.Now().UnixNano())}
}

// NewModuleWithEventBus explicitly opts the notification module into a
// producer/consumer EventBus. The default NewModule path remains local and
// does not construct Kafka. publisher sends durable Outbox events to the bus;
// consumerDest receives consumed events through a real ChannelAdapter.
func NewModuleWithEventBus(store EventStore, bus EventBus, consumerDest ChannelAdapter, internalToken string) *Module {
	m := NewModule(store, consumerDest, internalToken)
	if bus != nil {
		m.publisher = bus
		m.consumer = bus
		m.consumerDest = consumerDest
		m.eventBusClose = bus
	}
	return m
}

func (m *Module) Name() string { return "notification" }
func (m *Module) Start(ctx context.Context) error {
	if m.store == nil {
		return errors.New("notification store is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return ErrModuleClosed
	}
	if m.started {
		m.lifecycleMu.Unlock()
		return ErrModuleStarted
	}
	m.started = true
	m.lifecycleMu.Unlock()
	// Migration is deployment-owned; worker startup must not execute DDL.
	// 迁移由部署阶段负责，Worker启动不得执行DDL。
	if m.adapter != nil || m.publisher != nil {
		workerCtx, cancel := context.WithCancel(ctx)
		m.workerCancel = cancel
		m.workerDone = make(chan struct{})
		go m.runWorker(workerCtx)
	}
	if m.consumer != nil && m.consumerDest != nil {
		consumerCtx, cancel := context.WithCancel(ctx)
		// The consumer shares the module lifecycle but has a separate cancel
		// handle so Close can drain it before closing the underlying bus.
		if m.workerCancel == nil {
			m.workerCancel = cancel
		} else {
			previousCancel := m.workerCancel
			m.workerCancel = func() {
				previousCancel()
				cancel()
			}
		}
		m.consumerDone = make(chan struct{})
		go m.runConsumer(consumerCtx)
	}
	return nil
}
func (m *Module) Ready() error {
	if m.store == nil {
		return errors.New("notification store is required")
	}
	m.errorMu.RLock()
	defer m.errorMu.RUnlock()
	if m.workerErr != nil {
		return fmt.Errorf("notification worker failed: %w", m.workerErr)
	}
	if m.consumerErr != nil {
		return fmt.Errorf("notification consumer failed: %w", m.consumerErr)
	}
	return nil
}

func (m *Module) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.lifecycleMu.Lock()
	if m.closed {
		m.lifecycleMu.Unlock()
		return ErrModuleClosed
	}
	m.closed = true
	m.lifecycleMu.Unlock()
	if m.workerCancel != nil {
		m.workerCancel()
	}
	// Closing the bus after cancellation is what unblocks adapters whose
	// Consume call is waiting on a broker read. EventBus adapters must make
	// Close safe during an in-flight Consume and must not commit offsets while
	// shutdown is draining.
	var closeErr error
	if m.eventBusClose != nil {
		closeErr = m.eventBusClose.Close()
	}
	var waitErr error
	for _, done := range []chan struct{}{m.workerDone, m.consumerDone} {
		if done == nil {
			continue
		}
		select {
		case <-done:
		case <-ctx.Done():
			waitErr = errors.Join(waitErr, ctx.Err())
		}
	}
	return errors.Join(waitErr, closeErr)
}

func (m *Module) runWorker(ctx context.Context) {
	defer close(m.workerDone)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	owner := "platform-notification-worker"
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.dispatchBatch(ctx, owner)
		}
	}
}

func (m *Module) dispatchBatch(ctx context.Context, owner string) {
	store, ok := m.store.(EventStore)
	if !ok || (m.adapter == nil && m.publisher == nil) {
		return
	}
	events, err := store.Claim(owner, 20, time.Now().UTC(), 30*time.Second)
	if err != nil {
		m.recordWorkerError(err)
		return
	}
	for _, event := range events {
		var dispatchErr error
		if m.publisher != nil {
			dispatchErr = m.publisher.Publish(ctx, event)
		} else {
			dispatchErr = m.adapter.Send(ctx, event)
		}
		if dispatchErr != nil {
			if markErr := store.MarkFailed(event.ID, owner, time.Now().UTC(), 5); markErr != nil {
				m.recordWorkerError(errors.Join(dispatchErr, markErr))
			}
			continue
		}
		if err := store.MarkPublished(event.ID, owner); err != nil {
			m.recordWorkerError(err)
		}
	}
}

func (m *Module) runConsumer(ctx context.Context) {
	defer close(m.consumerDone)
	if m.consumer == nil || m.consumerDest == nil {
		return
	}
	if offsetConsumer, ok := m.consumer.(OffsetEventConsumer); ok {
		err := offsetConsumer.ConsumeMessages(ctx, func(handlerCtx context.Context, message EventMessage) DeliveryResult {
			if err := message.Validate(); err != nil {
				// A malformed or terminal-state event can never succeed on a
				// channel retry. Ask the broker adapter to DLQ it before it
				// commits the source offset.
				return DeadLetter(err)
			}
			if err := m.deliverConsumed(handlerCtx, message.Event); err != nil {
				if errors.Is(err, ErrEventDeliveryDeadLetter) {
					return DeadLetter(err)
				}
				return Retry(err)
			}
			return Ack()
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			m.recordConsumerError(err)
		}
		return
	}
	// A legacy consumer owns commit/DLQ decisions internally. Returning the
	// ChannelAdapter error is still important: a correctly implemented adapter
	// must leave that offset uncommitted for replay.
	err := m.consumer.Consume(ctx, func(handlerCtx context.Context, event Event) error {
		return m.deliverConsumed(handlerCtx, event)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		m.recordConsumerError(err)
	}
}

func (m *Module) deliverConsumed(ctx context.Context, event Event) error {
	if m.consumerDest == nil {
		return ErrAdapterUnavailable
	}
	store, ok := m.store.(DeliveryStore)
	if !ok {
		// A custom remote EventStore may provide its own consumer-side
		// idempotency. Keep compatibility with that Port while the built-in SQL
		// and memory stores use the durable ledger below.
		return m.consumerDest.Send(ctx, event)
	}
	owner := m.consumerOwner
	if owner == "" {
		owner = "platform-notification-consumer"
	}
	claim, err := store.ClaimDelivery(event, owner, time.Now().UTC(), 30*time.Second)
	if err != nil {
		if errors.Is(err, ErrDeliveryInProgress) {
			return err
		}
		return fmt.Errorf("claim notification delivery: %w", err)
	}
	if claim.Delivered || !claim.Acquired {
		return nil
	}
	if err := m.consumerDest.Send(ctx, event); err != nil {
		if markErr := store.MarkDeliveryFailed(event.ID, owner, time.Now().UTC(), 5, err); markErr != nil {
			return errors.Join(err, markErr)
		}
		return err
	}
	if err := store.MarkDeliverySucceeded(event.ID, owner); err != nil {
		return err
	}
	return nil
}

func (m *Module) recordWorkerError(err error) {
	if err == nil {
		return
	}
	m.errorMu.Lock()
	m.workerErr = err
	m.errorMu.Unlock()
}

func (m *Module) recordConsumerError(err error) {
	if err == nil {
		return
	}
	m.errorMu.Lock()
	m.consumerErr = err
	m.errorMu.Unlock()
}

func (m *Module) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/events", m.events)
	mux.HandleFunc("/events/", m.event)
	mux.HandleFunc("/dead-letters", m.deadLetterList)
	mux.HandleFunc("/dead-letters/", m.deadLetterAction)
	mux.HandleFunc("/inbox", m.recipientInbox)
	return mux
}

func (m *Module) events(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "" {
		m.writeError(w, http.StatusForbidden, "INTERNAL_NOTIFICATION_ONLY")
		return
	}
	if r.Method != http.MethodPost {
		m.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var event Event
	if err := decode(r, &event); err != nil {
		m.writeError(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	stored, err := m.store.Enqueue(event)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			m.writeError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT")
			return
		}
		m.writeError(w, http.StatusBadRequest, "INVALID_EVENT")
		return
	}
	m.writeJSON(w, http.StatusAccepted, stored)
}

func (m *Module) event(w http.ResponseWriter, r *http.Request) {
	if !m.authorized(r) {
		m.writeError(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if r.Header.Get("X-Browser-Module") != "" {
		m.writeError(w, http.StatusForbidden, "INTERNAL_NOTIFICATION_ONLY")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/events/"), "/"), "/")
	if len(parts) != 2 || parts[1] != "dispatch" || r.Method != http.MethodPost {
		m.writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if m.adapter == nil {
		m.writeError(w, http.StatusServiceUnavailable, "CHANNEL_ADAPTER_UNAVAILABLE")
		return
	}
	if err := (Dispatcher{Store: m.store, Adapter: m.adapter}).Dispatch(r.Context(), parts[0], "platform-notification-worker"); err != nil {
		if errors.Is(err, ErrClaimLost) {
			m.writeError(w, http.StatusConflict, "CLAIM_LOST")
			return
		}
		m.writeError(w, http.StatusInternalServerError, "DELIVERY_FAILED")
		return
	}
	m.writeJSON(w, http.StatusOK, map[string]any{"event_id": parts[0], "status": Published})
}

func (m *Module) authorized(r *http.Request) bool {
	if m.internalToken == "" {
		return true
	}
	value := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		value = strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	}
	return len(value) == len(m.internalToken) && subtle.ConstantTimeCompare([]byte(value), []byte(m.internalToken)) == 1
}

func decode(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("multiple json values")
	}
	return nil
}

func (m *Module) writeError(w http.ResponseWriter, status int, code string) {
	m.writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func (m *Module) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var _ bootstrap.Module = (*Module)(nil)
var _ bootstrap.ReadyModule = (*Module)(nil)
