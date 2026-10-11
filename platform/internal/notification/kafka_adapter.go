package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// KafkaPublisher is the narrow boundary used by the notification module.
// The platform owns event semantics while a deployment supplies the Kafka
// client, allowing a later worker or remote Event Bus to replace this adapter.
// KafkaPublisher 是通知模块使用的窄边界；平台拥有事件语义，部署环境注入
// Kafka 客户端，后续可无侵入替换为独立 Worker 或远程事件总线。
type KafkaPublisher interface {
	Publish(context.Context, string, string, []byte, map[string]string) error
}

// KafkaAdapter turns an immutable outbox Event into one Kafka message. It does
// not acknowledge the outbox: Dispatcher remains responsible for Claim/Mark
// state transitions, so a publish failure is retryable and never a silent ack.
// KafkaAdapter 只负责把不可变 Outbox 事件编码成 Kafka 消息，不确认 Outbox；
// Dispatcher 继续负责 Claim/Mark 状态迁移，发布失败可重试且不会静默确认。
type KafkaAdapter struct {
	Publisher KafkaPublisher
	// Consumer and Closer are injected by the deployment-specific Kafka
	// adapter. Keeping them as narrow ports means this package can verify
	// lifecycle and delivery semantics without constructing a broker client.
	Consumer       EventConsumer
	OffsetConsumer OffsetEventConsumer
	Closer         io.Closer
}

// Publish implements EventPublisher for an injected Kafka client. A concrete
// Kafka EventBus can embed or wrap this adapter and provide Consume/Close.
func (a KafkaAdapter) Publish(ctx context.Context, event Event) error {
	return a.Send(ctx, event)
}

func (a KafkaAdapter) Send(ctx context.Context, event Event) error {
	if a.Publisher == nil {
		return ErrAdapterUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("publish notification event: context is required")
	}
	if err := event.ValidateForDelivery(); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode kafka notification event: %w", err)
	}
	headers := map[string]string{
		"event_id":        event.ID,
		"tenant_id":       event.TenantID,
		"department_id":   event.DepartmentID,
		"application_id":  event.ApplicationID,
		"event_type":      event.EventType,
		"idempotency_key": event.ID,
		"content_type":    "application/json",
	}
	if err := a.Publisher.Publish(ctx, event.Topic, event.PartitionKey, payload, headers); err != nil {
		return fmt.Errorf("publish notification event: %w", err)
	}
	return nil
}

// Consume implements the compatibility consumer contract. Deployments that
// have broker offsets available should inject OffsetConsumer and use
// ConsumeMessages instead; this method adapts successful/failing handlers to
// Ack/Retry while preserving the adapter's commit policy.
func (a KafkaAdapter) Consume(ctx context.Context, handler func(context.Context, Event) error) error {
	if a.Consumer != nil {
		return a.Consumer.Consume(ctx, handler)
	}
	if a.OffsetConsumer != nil {
		return a.OffsetConsumer.ConsumeMessages(ctx, func(handlerCtx context.Context, message EventMessage) DeliveryResult {
			if handler == nil {
				return Retry(ErrEventConsumerUnavailable)
			}
			if err := handler(handlerCtx, message.Event); err != nil {
				return Retry(err)
			}
			return Ack()
		})
	}
	return ErrEventConsumerUnavailable
}

func (a KafkaAdapter) ConsumeMessages(ctx context.Context, handler func(context.Context, EventMessage) DeliveryResult) error {
	if a.OffsetConsumer == nil {
		return ErrEventConsumerUnavailable
	}
	return a.OffsetConsumer.ConsumeMessages(ctx, handler)
}

func (a KafkaAdapter) Close() error {
	if a.Closer == nil {
		return nil
	}
	if err := a.Closer.Close(); err != nil {
		return fmt.Errorf("close notification event bus: %w", err)
	}
	return nil
}

// Ensure a nil publisher is handled as a controlled adapter failure rather
// than a panic in a background worker.
var _ ChannelAdapter = KafkaAdapter{}
var _ EventBus = KafkaAdapter{}
var _ OffsetEventConsumer = KafkaAdapter{}
