package notification

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type offsetBusStub struct {
	mu       sync.Mutex
	messages []EventMessage
	results  []DeliveryResult
	closed   bool
	closeErr error
}

func (b *offsetBusStub) Publish(context.Context, Event) error { return nil }

func (b *offsetBusStub) Consume(context.Context, func(context.Context, Event) error) error {
	return ErrEventConsumerUnavailable
}

func (b *offsetBusStub) ConsumeMessages(ctx context.Context, handler func(context.Context, EventMessage) DeliveryResult) error {
	for _, message := range b.messages {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		result := handler(ctx, message)
		b.mu.Lock()
		b.results = append(b.results, result)
		b.mu.Unlock()
	}
	return nil
}

func (b *offsetBusStub) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return b.closeErr
}

type recordingChannel struct {
	mu    sync.Mutex
	calls []Event
	err   error
}

func (c *recordingChannel) Send(_ context.Context, event Event) error {
	c.mu.Lock()
	c.calls = append(c.calls, event)
	c.mu.Unlock()
	return c.err
}

func TestKafkaAdapterCanPublishClaimedOutboxEvent(t *testing.T) {
	publisher := &recordingPublisher{}
	event := eventFixture()
	event.Status = Publishing
	event.Attempts = 2
	if err := (KafkaAdapter{Publisher: publisher}).Send(context.Background(), event); err != nil {
		t.Fatalf("claimed event must be publishable: %v", err)
	}
}

func TestOffsetConsumerMapsChannelFailureToRetry(t *testing.T) {
	bus := &offsetBusStub{messages: []EventMessage{{Event: eventFixture(), Partition: 1, Offset: 7, Attempt: 1}}}
	channel := &recordingChannel{err: errors.New("provider timeout")}
	module := NewModuleWithEventBus(NewStore(), bus, channel, "")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		bus.mu.Lock()
		ready := len(bus.results) == 1
		bus.mu.Unlock()
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := module.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.results) != 1 || bus.results[0].Action != DeliveryRetry || !errors.Is(bus.results[0].Err, channel.err) {
		t.Fatalf("channel failure must remain replayable: %#v", bus.results)
	}
	if !bus.closed {
		t.Fatal("module close must close the injected event bus")
	}
}

func TestOffsetConsumerDeduplicatesReplayedEventBeforeChannelAdapter(t *testing.T) {
	event := eventFixture()
	bus := &offsetBusStub{messages: []EventMessage{
		{Event: event, Partition: 1, Offset: 7, Attempt: 0},
		{Event: event, Partition: 1, Offset: 8, Attempt: 0},
	}}
	channel := &recordingChannel{}
	module := NewModuleWithEventBus(NewStore(), bus, channel, "")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		bus.mu.Lock()
		ready := len(bus.results) == 2
		bus.mu.Unlock()
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := module.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(channel.calls) != 1 {
		t.Fatalf("replayed event must invoke ChannelAdapter once, got %d calls", len(channel.calls))
	}
}

func TestOffsetConsumerMapsMalformedEventToDLQ(t *testing.T) {
	malformed := eventFixture()
	malformed.Status = Published
	bus := &offsetBusStub{messages: []EventMessage{{Event: malformed, Partition: 0, Offset: 9}}}
	channel := &recordingChannel{}
	module := NewModuleWithEventBus(NewStore(), bus, channel, "")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		bus.mu.Lock()
		ready := len(bus.results) == 1
		bus.mu.Unlock()
		if ready || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := module.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.results) != 1 || bus.results[0].Action != DeliveryDeadLetter || !errors.Is(bus.results[0].Err, ErrInvalidEvent) {
		t.Fatalf("malformed event must be dead-lettered: %#v", bus.results)
	}
	if len(channel.calls) != 0 {
		t.Fatalf("malformed event must not reach channel: %d calls", len(channel.calls))
	}
}

func TestModuleReadyReportsConsumerFailure(t *testing.T) {
	want := errors.New("consumer stopped")
	bus := &offsetBusStubWithError{offsetBusStub: offsetBusStub{}, err: want}
	module := NewModuleWithEventBus(NewStore(), bus, &recordingChannel{}, "")
	if err := module.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if err := module.Ready(); err != nil {
			if !errors.Is(err, want) {
				t.Fatalf("unexpected consumer error: %v", err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("consumer failure was not surfaced through Ready")
		}
		time.Sleep(time.Millisecond)
	}
	_ = module.Close(context.Background())
}

type offsetBusStubWithError struct {
	offsetBusStub
	err error
}

func (b *offsetBusStubWithError) ConsumeMessages(context.Context, func(context.Context, EventMessage) DeliveryResult) error {
	return b.err
}

func TestDeliveryResultDefaultsMakeFailureReasonExplicit(t *testing.T) {
	if result := Retry(nil); result.Action != DeliveryRetry || !errors.Is(result.Err, ErrEventDeliveryRetry) {
		t.Fatalf("Retry(nil) must be explicit: %#v", result)
	}
	if result := DeadLetter(nil); result.Action != DeliveryDeadLetter || !errors.Is(result.Err, ErrEventDeliveryDeadLetter) {
		t.Fatalf("DeadLetter(nil) must be explicit: %#v", result)
	}
}
