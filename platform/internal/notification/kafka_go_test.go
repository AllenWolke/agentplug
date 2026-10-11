package notification

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

func TestKafkaConsumerTopicsIncludesIdentityAndRejectsDLQLoop(t *testing.T) {
	topics, err := kafkaConsumerTopics(KafkaGoConfig{Topic: "platform.audit", AdditionalTopics: []string{"agent-platform.identity.v1", "platform.audit", " agent-platform.identity.v1 "}, DLQTopic: "dead"})
	if err != nil || !reflect.DeepEqual(topics, []string{"platform.audit", "agent-platform.identity.v1"}) {
		t.Fatalf("consumer topics: %v, %v", topics, err)
	}
	for _, topic := range []string{"", " ", "dead"} {
		if _, err := kafkaConsumerTopics(KafkaGoConfig{Topic: "platform.audit", AdditionalTopics: []string{topic}, DLQTopic: "dead"}); err == nil {
			t.Fatalf("invalid consumer topic accepted: %q", topic)
		}
	}
}

type kafkaReaderFake struct {
	messages []kafka.Message
	commits  []kafka.Message
	closed   bool
}

// kafkaReaderAdvancesOnFetch mirrors kafka-go's local read cursor: fetching a
// message advances the cursor even when the source offset has not been
// committed.  A Retry must therefore stay inside the current-message loop.
// kafkaReaderAdvancesOnFetch 模拟 kafka-go 的本地读取游标：即使尚未提交
// offset，Fetch 也会推进游标；Retry 必须留在当前消息循环中。
type kafkaReaderAdvancesOnFetch struct {
	messages []kafka.Message
	index    int
	commits  []kafka.Message
	fetches  int
}

func (r *kafkaReaderAdvancesOnFetch) FetchMessage(ctx context.Context) (kafka.Message, error) {
	if r.index >= len(r.messages) {
		if err := ctx.Err(); err != nil {
			return kafka.Message{}, err
		}
		return kafka.Message{}, errKafkaReaderDone
	}
	message := r.messages[r.index]
	r.index++
	r.fetches++
	return message, nil
}

func (r *kafkaReaderAdvancesOnFetch) CommitMessages(_ context.Context, messages ...kafka.Message) error {
	r.commits = append(r.commits, messages...)
	return nil
}

func (r *kafkaReaderAdvancesOnFetch) Close() error { return nil }

func (r *kafkaReaderFake) FetchMessage(ctx context.Context) (kafka.Message, error) {
	if len(r.messages) == 0 {
		if err := ctx.Err(); err != nil {
			return kafka.Message{}, err
		}
		return kafka.Message{}, errKafkaReaderDone
	}
	return r.messages[0], nil
}

func (r *kafkaReaderFake) CommitMessages(_ context.Context, messages ...kafka.Message) error {
	r.commits = append(r.commits, messages...)
	if len(r.messages) > 0 {
		r.messages = r.messages[1:]
	}
	return nil
}

func (r *kafkaReaderFake) Close() error {
	r.closed = true
	return nil
}

type kafkaWriterFake struct {
	messages []kafka.Message
	closed   bool
	fail     bool
}

func (w *kafkaWriterFake) WriteMessages(_ context.Context, messages ...kafka.Message) error {
	if w.fail {
		return errKafkaWriterFake
	}
	w.messages = append(w.messages, messages...)
	return nil
}

func (w *kafkaWriterFake) Close() error {
	w.closed = true
	return nil
}

func TestKafkaGoEventBusRetriesThenDLQsAndCommitsOnlyAfterDLQ(t *testing.T) {
	reader := &kafkaReaderFake{messages: []kafka.Message{{Topic: "platform.audit", Partition: 2, Offset: 11, Key: []byte("aggregate"), Value: []byte(`{"not":"an event"}`)}}}
	writer := &kafkaWriterFake{}
	bus := &KafkaGoEventBus{reader: reader, writer: writer, dlqTopic: "platform.audit-dlq", max: 2, backoff: time.Nanosecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	err := bus.ConsumeMessages(ctx, func(_ context.Context, message EventMessage) DeliveryResult {
		calls++
		if calls == 1 {
			return Retry(errors.New("channel timeout"))
		}
		return Retry(errors.New("channel timeout again"))
	})
	if !errors.Is(err, errKafkaReaderDone) {
		t.Fatalf("fake reader should stop after committed message, got %v", err)
	}
	if calls != 2 || len(reader.commits) != 1 {
		t.Fatalf("expected two attempts and one source commit, calls=%d commits=%d", calls, len(reader.commits))
	}
	if len(writer.messages) != 1 || writer.messages[0].Topic != "platform.audit-dlq" {
		t.Fatalf("expected one DLQ message, got %#v", writer.messages)
	}
	if got := headerValue(writer.messages[0].Headers, "failure_reason"); got == "" {
		t.Fatal("DLQ must retain failure reason")
	}
}

func TestKafkaGoEventBusRetriesSameFetchedMessageBeforeAdvancing(t *testing.T) {
	valid := func(id string) []byte {
		return []byte(`{"id":"` + id + `","tenant_id":"tenant","department_id":"department","application_id":"application","topic":"platform.audit","event_type":"probe","partition_key":"aggregate","payload":{}}`)
	}
	reader := &kafkaReaderAdvancesOnFetch{messages: []kafka.Message{
		{Topic: "platform.audit", Partition: 0, Offset: 11, Key: []byte("one"), Value: valid("event-one")},
		{Topic: "platform.audit", Partition: 0, Offset: 12, Key: []byte("two"), Value: valid("event-two")},
	}}
	writer := &kafkaWriterFake{}
	bus := &KafkaGoEventBus{reader: reader, writer: writer, dlqTopic: "platform.audit-dlq", max: 3, backoff: time.Nanosecond}
	var offsets []int64
	var attempts []int
	err := bus.ConsumeMessages(context.Background(), func(_ context.Context, message EventMessage) DeliveryResult {
		offsets = append(offsets, message.Offset)
		attempts = append(attempts, message.Attempt)
		if message.Offset == 11 && message.Attempt == 0 {
			return Retry(errors.New("transient channel failure"))
		}
		return Ack()
	})
	if !errors.Is(err, errKafkaReaderDone) {
		t.Fatalf("fake reader should stop after both committed messages, got %v", err)
	}
	if got, want := fmt.Sprint(offsets), "[11 11 12]"; got != want {
		t.Fatalf("retry must reuse the fetched offset before advancing: got %s want %s", got, want)
	}
	if got, want := fmt.Sprint(attempts), "[0 1 0]"; got != want {
		t.Fatalf("unexpected delivery attempts: got %s want %s", got, want)
	}
	if reader.fetches != 2 || len(reader.commits) != 2 {
		t.Fatalf("expected two fetches and two commits, fetches=%d commits=%d", reader.fetches, len(reader.commits))
	}
}

func TestKafkaGoEventBusLeavesOffsetUncommittedWhenDLQFails(t *testing.T) {
	reader := &kafkaReaderFake{messages: []kafka.Message{{Topic: "platform.audit", Partition: 0, Offset: 3, Value: []byte(`{`)}}}
	writer := &kafkaWriterFake{fail: true}
	bus := &KafkaGoEventBus{reader: reader, writer: writer, dlqTopic: "platform.audit-dlq", max: 3, backoff: time.Nanosecond}
	err := bus.ConsumeMessages(context.Background(), func(_ context.Context, _ EventMessage) DeliveryResult {
		return DeadLetter(errors.New("malformed"))
	})
	if !errors.Is(err, errKafkaWriterFake) {
		t.Fatalf("expected DLQ writer error, got %v", err)
	}
	if len(reader.commits) != 0 {
		t.Fatal("source offset must stay uncommitted when DLQ publication fails")
	}
}

var errKafkaWriterFake = errors.New("Kafka fake writer unavailable")
var errKafkaReaderDone = errors.New("Kafka fake reader done")

func headerValue(headers []kafka.Header, key string) string {
	for _, header := range headers {
		if header.Key == key {
			return string(header.Value)
		}
	}
	return ""
}
