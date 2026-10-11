package notification

// This file is the platform-owned Kafka boundary. It intentionally keeps
// kafka-go types here, at the edge of the process, so the Outbox/Dispatcher
// and future remote notification service continue to depend only on ports.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaGoConfig is the validated deployment configuration for the concrete
// Kafka adapter. Topic provisioning is deliberately external: this adapter
// never creates topics as a side effect of starting the platform process.
type KafkaGoConfig struct {
	Brokers  []string
	ClientID string
	Topic    string
	// AdditionalTopics are consumed by this group, in addition to Topic.
	// Topic names remain explicit; provisioning is owned by deployment.
	AdditionalTopics []string
	GroupID          string
	DLQTopic         string
	MaxAttempts      int
	RetryBackoff     time.Duration
	Dialer           *kafka.Dialer
	Transport        *kafka.Transport
	DeadLetters      DeadLetterSink
}

// KafkaGoEventBus implements EventBus and OffsetEventConsumer over kafka-go.
// The broker offset is committed only after Ack or a successful DLQ write.
// A ChannelAdapter failure leaves the source message uncommitted so Kafka can
// replay it after the bounded retry backoff or process restart.
type KafkaGoEventBus struct {
	writer      kafkaMessageWriter
	reader      kafkaMessageReader
	dlqTopic    string
	max         int
	backoff     time.Duration
	group       string
	deadLetters DeadLetterSink

	closeOnce sync.Once
	closeErr  error
}

type kafkaMessageWriter interface {
	WriteMessages(context.Context, ...kafka.Message) error
	Close() error
}

type kafkaMessageReader interface {
	FetchMessage(context.Context) (kafka.Message, error)
	CommitMessages(context.Context, ...kafka.Message) error
	Close() error
}

// NewKafkaGoEventBus creates the real Kafka adapter. It does not dial or
// claim a broker message until Publish/ConsumeMessages is called, which keeps
// construction deterministic and makes readiness failures observable through
// the module lifecycle rather than silently falling back to local delivery.
func NewKafkaGoEventBus(cfg KafkaGoConfig) (*KafkaGoEventBus, error) {
	brokers := make([]string, 0, len(cfg.Brokers))
	for _, broker := range cfg.Brokers {
		if value := strings.TrimSpace(broker); value != "" {
			brokers = append(brokers, value)
		}
	}
	if len(brokers) == 0 || strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.Topic) == "" || strings.TrimSpace(cfg.GroupID) == "" || strings.TrimSpace(cfg.DLQTopic) == "" {
		return nil, errors.New("Kafka brokers, client id, topic, group and DLQ topic are required")
	}
	if cfg.MaxAttempts <= 0 || cfg.MaxAttempts > 100 {
		return nil, errors.New("Kafka max attempts must be between 1 and 100")
	}
	if cfg.RetryBackoff <= 0 || cfg.RetryBackoff > time.Minute {
		return nil, errors.New("Kafka retry backoff must be positive and at most one minute")
	}
	if !deadLetterToken(cfg.GroupID, 255) || !deadLetterToken(cfg.DLQTopic, 255) {
		return nil, errors.New("invalid Kafka group or DLQ topic")
	}
	topics, err := kafkaConsumerTopics(cfg)
	if err != nil {
		return nil, err
	}
	transport := cfg.Transport
	if transport == nil {
		transport = &kafka.Transport{ClientID: cfg.ClientID}
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &kafka.Dialer{ClientID: cfg.ClientID, Timeout: 10 * time.Second, DualStack: true}
	}
	writer := &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Balancer:               &kafka.Hash{},
		RequiredAcks:           kafka.RequireAll,
		Async:                  false,
		BatchTimeout:           10 * time.Millisecond,
		AllowAutoTopicCreation: false,
		Transport:              transport,
	}
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		GroupTopics:    topics,
		GroupID:        cfg.GroupID,
		MinBytes:       1,
		MaxBytes:       10e6,
		MaxWait:        time.Second,
		CommitInterval: 0,
		StartOffset:    kafka.FirstOffset,
		Dialer:         dialer,
	})
	return &KafkaGoEventBus{writer: writer, reader: reader, dlqTopic: cfg.DLQTopic, max: cfg.MaxAttempts, backoff: cfg.RetryBackoff, group: cfg.GroupID, deadLetters: cfg.DeadLetters}, nil
}

func kafkaConsumerTopics(cfg KafkaGoConfig) ([]string, error) {
	topics := make([]string, 0, 1+len(cfg.AdditionalTopics))
	seen := make(map[string]bool)
	for _, candidate := range append([]string{cfg.Topic}, cfg.AdditionalTopics...) {
		topic := strings.TrimSpace(candidate)
		if topic == "" || topic == strings.TrimSpace(cfg.DLQTopic) {
			return nil, errors.New("Kafka consumer topics must be nonempty and exclude the DLQ")
		}
		if !seen[topic] {
			topics = append(topics, topic)
			seen[topic] = true
		}
	}
	return topics, nil
}

func (b *KafkaGoEventBus) Publish(ctx context.Context, event Event) error {
	if b == nil || b.writer == nil {
		return ErrEventBusUnavailable
	}
	if err := event.ValidateForDelivery(); err != nil {
		return err
	}
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode Kafka notification event: %w", err)
	}
	headers := []kafka.Header{
		{Key: "event_id", Value: []byte(event.ID)},
		{Key: "event_type", Value: []byte(event.EventType)},
		{Key: "idempotency_key", Value: []byte(event.ID)},
		{Key: "tenant_id", Value: []byte(event.TenantID)},
		{Key: "department_id", Value: []byte(event.DepartmentID)},
		{Key: "application_id", Value: []byte(event.ApplicationID)},
		{Key: "content_type", Value: []byte("application/json")},
	}
	if err := b.writer.WriteMessages(ctx, kafka.Message{Topic: event.Topic, Key: []byte(event.PartitionKey), Value: body, Headers: headers}); err != nil {
		return fmt.Errorf("publish Kafka notification event: %w", err)
	}
	return nil
}

func (b *KafkaGoEventBus) Consume(ctx context.Context, handler func(context.Context, Event) error) error {
	if handler == nil {
		return ErrEventConsumerUnavailable
	}
	return b.ConsumeMessages(ctx, func(handlerCtx context.Context, message EventMessage) DeliveryResult {
		if err := handler(handlerCtx, message.Event); err != nil {
			return Retry(err)
		}
		return Ack()
	})
}

func (b *KafkaGoEventBus) ConsumeMessages(ctx context.Context, handler func(context.Context, EventMessage) DeliveryResult) error {
	if b == nil || b.reader == nil || b.writer == nil {
		return ErrEventConsumerUnavailable
	}
	if handler == nil {
		return ErrEventConsumerUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Kafka offsets do not carry a delivery-attempt counter. Keep the attempt
	// counter in the inner loop for the currently fetched message. FetchMessage
	// advances kafka-go's local read position even before CommitMessages, so a
	// Retry must invoke the handler again for this exact message instead of
	// fetching the next record. After a process restart the broker replays the
	// uncommitted offset from zero; Event.ID and the durable delivery ledger
	// keep that replay idempotent.
	// Kafka offset 没有携带投递次数。次数必须保存在当前消息的内层循环中。
	// kafka-go 即使尚未 CommitMessages 也会推进本地读取位置，因此 Retry
	// 必须对同一条消息再次调用处理器，不能直接 Fetch 下一条消息。
	for {
		message, err := b.reader.FetchMessage(ctx)
		if err != nil {
			return err
		}
		group := b.group
		if group == "" {
			group = "legacy-unconfigured"
		} // only hand-built legacy adapters
		source, err := deadLetterSource(group, message)
		if err != nil {
			return err
		}
		event, decodeErr := decodeKafkaEvent(message.Value)
		headers := kafkaHeaders(message.Headers)
		if decodeErr != nil {
			headers["decode_error"] = truncateKafkaError(decodeErr)
		}
		for attempt := 0; ; attempt++ {
			actualAttempt := attempt + 1
			var prior DeadLetterAttempt
			if b.deadLetters != nil {
				prior, err = b.deadLetters.StartAttempt(ctx, source, b.max)
				if err != nil {
					return err
				}
				actualAttempt = prior.Attempts
				if prior.Acknowledged || prior.Published {
					if err = b.reader.CommitMessages(ctx, message); err != nil {
						return err
					}
					break
				}
			}
			result := DeadLetter(ErrEventDeliveryDeadLetter)
			if !prior.Exhausted {
				result = handler(ctx, EventMessage{Event: event, Topic: message.Topic, Partition: message.Partition, Offset: message.Offset, Key: string(message.Key), Headers: headers, Attempt: actualAttempt - 1})
			}
			if result.Action == DeliveryRetry && actualAttempt >= b.max {
				result = DeadLetter(errors.Join(result.Err, ErrEventDeliveryDeadLetter))
			}
			switch result.Action {
			case DeliveryAck:
				if result.Err != nil {
					return errors.New("Kafka Ack cannot carry an error")
				}
				if b.deadLetters != nil {
					if err = b.deadLetters.MarkAcknowledged(ctx, source); err != nil {
						return err
					}
				}
				if err := b.reader.CommitMessages(ctx, message); err != nil {
					return fmt.Errorf("commit Kafka notification offset: %w", err)
				}
				// Only fetch the next record after the source offset is durable.
				// 仅在源 offset 持久提交后读取下一条消息。
				break
			case DeliveryRetry:
				if result.Err == nil {
					result.Err = ErrEventDeliveryRetry
				}
				if err := waitKafkaRetry(ctx, b.backoff, actualAttempt-1); err != nil {
					return errors.Join(result.Err, err)
				}
				// Do not call FetchMessage here: the same Kafka record must be
				// redelivered until it is acknowledged or sent to the DLQ.
				// 这里不能 FetchMessage，必须继续重试同一条 Kafka 记录。
				continue
			case DeliveryDeadLetter:
				if result.Err == nil {
					result.Err = ErrEventDeliveryDeadLetter
				}
				if err := b.publishKafkaDLQ(ctx, source, message, result.Err, actualAttempt); err != nil {
					// Keep the source offset uncommitted when DLQ is unavailable. A
					// restart/retry must not lose a malformed or terminal event.
					return err
				}
				if err := b.reader.CommitMessages(ctx, message); err != nil {
					return fmt.Errorf("commit Kafka DLQ source offset: %w", err)
				}
				break
			default:
				return fmt.Errorf("unknown Kafka delivery action %d", result.Action)
			}
			if result.Action == DeliveryAck || result.Action == DeliveryDeadLetter {
				break
			}
		}
	}
}

func decodeKafkaEvent(raw []byte) (Event, error) {
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return Event{}, fmt.Errorf("decode Kafka notification event: %w", err)
	}
	return event, nil
}

func kafkaHeaders(headers []kafka.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for _, header := range headers {
		result[header.Key] = string(header.Value)
	}
	return result
}

func (b *KafkaGoEventBus) publishKafkaDLQ(ctx context.Context, source DeadLetterSource, message kafka.Message, cause error, attempts int) error {
	record, err := newDeadLetterRecord(source, message, cause, attempts)
	if err != nil {
		return err
	}
	if b.deadLetters != nil {
		if err = b.deadLetters.Quarantine(ctx, record); err != nil {
			return err
		}
	}
	// Key is the stable source identity. Do not copy arbitrary source headers,
	// exception text or user keys into diagnostic metadata.
	if err := b.writer.WriteMessages(ctx, kafka.Message{Topic: b.dlqTopic, Key: []byte(source.ID()), Value: message.Value, Headers: safeDeadLetterHeaders(record.Metadata), Time: time.Now().UTC()}); err != nil {
		return fmt.Errorf("publish Kafka notification DLQ: %w", err)
	}
	if b.deadLetters != nil {
		return b.deadLetters.MarkPublished(ctx, source)
	}
	return nil
}

func waitKafkaRetry(ctx context.Context, base time.Duration, attempt int) error {
	delay := base
	for i := 0; i < attempt && delay < 30*time.Second; i++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func truncateKafkaError(err error) string {
	return kafkaFailureCode(err)
}

func (b *KafkaGoEventBus) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		if b.reader != nil {
			b.closeErr = errors.Join(b.closeErr, b.reader.Close())
		}
		if b.writer != nil {
			b.closeErr = errors.Join(b.closeErr, b.writer.Close())
		}
	})
	return b.closeErr
}

var _ EventBus = (*KafkaGoEventBus)(nil)
var _ OffsetEventConsumer = (*KafkaGoEventBus)(nil)
