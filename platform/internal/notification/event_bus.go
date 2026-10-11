package notification

import (
	"context"
	"errors"
	"io"
)

// EventPublisher and EventConsumer keep Kafka (or another event bus) outside
// the notification domain. A concrete deployment may implement these ports
// with a Kafka client, while tests and local mode can keep the default direct
// Outbox -> ChannelAdapter path.
// EventPublisher/EventConsumer 将 Kafka 或其他事件总线隔离在通知领域之外。
// 生产部署可注入 Kafka 实现，本地模式仍使用默认 Outbox 直投通道。
type EventPublisher interface {
	Publish(context.Context, Event) error
}

type EventConsumer interface {
	Consume(context.Context, func(context.Context, Event) error) error
}

// EventMessage is the transport envelope supplied by an offset-aware event
// bus adapter. Offset and partition are intentionally metadata only: the
// notification domain never persists or mutates broker offsets. A delivery
// may be observed more than once, so Event.ID remains the idempotency key.
//
// EventMessage 是带 offset 的事件总线 Adapter 提供的传输信封。offset 和
// partition 只属于传输元数据，通知领域不持久化或修改 Broker offset；同一
// 投递可能重复到达，因此仍必须使用 Event.ID 做幂等键。
type EventMessage struct {
	Event     Event
	Topic     string
	Partition int
	Offset    int64
	Key       string
	Headers   map[string]string
	Attempt   int
}

func (m EventMessage) Validate() error {
	if err := m.Event.ValidateForDelivery(); err != nil {
		return err
	}
	if m.Partition < 0 || m.Offset < 0 || m.Attempt < 0 {
		return ErrInvalidEvent
	}
	return nil
}

// DeliveryAction tells an offset-aware adapter when it may commit a message.
// The adapter must commit only after Ack, must leave the offset uncommitted for
// Retry, and must publish a durable DLQ record before committing DeadLetter.
type DeliveryAction uint8

const (
	DeliveryAck DeliveryAction = iota + 1
	DeliveryRetry
	DeliveryDeadLetter
)

// DeliveryResult is returned by the platform handler to an offset-aware bus.
// Err is required for Retry/DeadLetter and is retained by the adapter as the
// failure reason; Ack must not carry an error.
type DeliveryResult struct {
	Action DeliveryAction
	Err    error
}

func Ack() DeliveryResult { return DeliveryResult{Action: DeliveryAck} }

func Retry(err error) DeliveryResult {
	if err == nil {
		err = ErrEventDeliveryRetry
	}
	return DeliveryResult{Action: DeliveryRetry, Err: err}
}

func DeadLetter(err error) DeliveryResult {
	if err == nil {
		err = ErrEventDeliveryDeadLetter
	}
	return DeliveryResult{Action: DeliveryDeadLetter, Err: err}
}

// OffsetEventConsumer is the stronger consumer contract for Kafka-like
// adapters. The adapter owns commit/DLQ mechanics and must implement:
//   - Ack: commit the source offset after successful ChannelAdapter delivery;
//   - Retry: do not commit, allowing redelivery after backoff/restart;
//   - DeadLetter: durably publish to DLQ, then commit only if the DLQ publish
//     succeeds. If DLQ publication fails, the source offset stays uncommitted.
//
// Keeping the older EventConsumer port below preserves compatibility with
// adapters that already own these decisions internally.
type OffsetEventConsumer interface {
	ConsumeMessages(context.Context, func(context.Context, EventMessage) DeliveryResult) error
}

var (
	ErrEventDeliveryRetry       = errors.New("notification event delivery retry requested")
	ErrEventDeliveryDeadLetter  = errors.New("notification event delivery dead-lettered")
	ErrEventConsumerUnavailable = errors.New("notification event consumer unavailable")
)

// EventBus is the lifecycle-aware event-bus port used by an optional worker.
// It deliberately does not expose offsets or Kafka-specific types to domain
// modules; the adapter owns those details and must commit only after the
// ChannelAdapter succeeds.
type EventBus interface {
	EventPublisher
	EventConsumer
	io.Closer
}

var ErrEventBusUnavailable = errors.New("notification event bus unavailable")
