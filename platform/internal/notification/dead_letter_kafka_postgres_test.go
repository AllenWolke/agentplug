package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lexagent/platform/internal/sqlutil"
	"github.com/segmentio/kafka-go"
)

type lostDeadLetterAcknowledgement struct {
	real  kafkaMessageWriter
	topic string
	lost  bool
}

func (w *lostDeadLetterAcknowledgement) WriteMessages(ctx context.Context, messages ...kafka.Message) error {
	if e := w.real.WriteMessages(ctx, messages...); e != nil {
		return e
	}
	if !w.lost && len(messages) > 0 && messages[0].Topic == w.topic {
		w.lost = true
		return errors.New("injected acknowledgement loss after real Kafka write")
	}
	return nil
}
func (w *lostDeadLetterAcknowledgement) Close() error { return w.real.Close() }

type observedKafkaCommit struct {
	real      kafkaMessageReader
	committed chan struct{}
	once      sync.Once
}

func (r *observedKafkaCommit) FetchMessage(ctx context.Context) (kafka.Message, error) {
	return r.real.FetchMessage(ctx)
}
func (r *observedKafkaCommit) CommitMessages(ctx context.Context, messages ...kafka.Message) error {
	if e := r.real.CommitMessages(ctx, messages...); e != nil {
		return e
	}
	r.once.Do(func() { close(r.committed) })
	return nil
}
func (r *observedKafkaCommit) Close() error { return r.real.Close() }

// A real broker acknowledges DLQ publication, then the acknowledgement is lost
// before SQL/offset confirmation. Restart must preserve the quarantine, submit
// the same source identity, and never run the original business handler again.
func TestDeadLetterRealKafkaPostgresLostAckAndRestart(t *testing.T) {
	broker := os.Getenv("AUTHORIZATION_ISOLATED_KAFKA_BROKER")
	if broker == "" {
		t.Skip("owned Kafka fixture required")
	}
	db, sink, _ := deadLetterDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	suffix := fmt.Sprint(time.Now().UnixNano())
	topic, dlq, group := "dlq-source-"+suffix, "dlq-destination-"+suffix, "dlq-consumer-"+suffix
	conn, e := kafka.DialContext(ctx, "tcp", broker)
	if e != nil {
		t.Fatal(e)
	}
	controller, e := conn.Controller()
	conn.Close()
	if e != nil {
		t.Fatal(e)
	}
	admin, e := kafka.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", controller.Host, controller.Port))
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	if e = admin.CreateTopics(kafka.TopicConfig{Topic: topic, NumPartitions: 1, ReplicationFactor: 1}, kafka.TopicConfig{Topic: dlq, NumPartitions: 1, ReplicationFactor: 1}); e != nil {
		t.Fatal(e)
	}
	event := Event{ID: "event-" + suffix, TenantID: "t1", DepartmentID: "d1", ApplicationID: "a1", Topic: topic, EventType: "fixture.v1", PartitionKey: "p1", Payload: map[string]any{"body": "PRIVATE_DLQ_BODY"}}
	body, _ := json.Marshal(event)
	producer := &kafka.Writer{Addr: kafka.TCP(broker), RequiredAcks: kafka.RequireAll, AllowAutoTopicCreation: false}
	if e = producer.WriteMessages(ctx, kafka.Message{Topic: topic, Key: []byte("PRIVATE_KEY"), Value: body, Headers: []kafka.Header{{Key: "authorization", Value: []byte("PRIVATE_HEADER")}}}); e != nil {
		t.Fatal(e)
	}
	producer.Close()
	cfg := KafkaGoConfig{Brokers: []string{broker}, ClientID: group, Topic: topic, GroupID: group, DLQTopic: dlq, MaxAttempts: 2, RetryBackoff: time.Millisecond, DeadLetters: sink}
	bus, e := NewKafkaGoEventBus(cfg)
	if e != nil {
		t.Fatal(e)
	}
	bus.writer = &lostDeadLetterAcknowledgement{real: bus.writer, topic: dlq}
	var calls atomic.Int32
	e = bus.ConsumeMessages(ctx, func(context.Context, EventMessage) DeliveryResult {
		calls.Add(1)
		return DeadLetter(errors.New("PRIVATE_ERROR_TOKEN"))
	})
	bus.Close()
	if e == nil || !strings.Contains(e.Error(), "injected acknowledgement loss") {
		t.Fatal("acknowledgement fault not exercised", e)
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected forward calls", calls.Load())
	}
	var id string
	var published bool
	var attempts int
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT source_id,published,attempts FROM platform_kafka_delivery_attempt WHERE source_json::jsonb->>'consumer_group'=?`), group).Scan(&id, &published, &attempts); e != nil || published || attempts != 1 {
		t.Fatal("lost acknowledgement manufactured receipt", published, attempts, e)
	}
	bus, e = NewKafkaGoEventBus(cfg)
	if e != nil {
		t.Fatal(e)
	}
	commit := &observedKafkaCommit{real: bus.reader, committed: make(chan struct{})}
	bus.reader = commit
	restartCtx, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() {
		finished <- bus.ConsumeMessages(restartCtx, func(context.Context, EventMessage) DeliveryResult { calls.Add(1); return Ack() })
	}()
	for !published {
		if ctx.Err() != nil {
			stop()
			bus.Close()
			t.Fatal("restart did not publish quarantine")
		}
		if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT published FROM platform_kafka_delivery_attempt WHERE source_id=?`), id).Scan(&published); e != nil {
			stop()
			bus.Close()
			t.Fatal(e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Observe a broker-confirmed CommitMessages, not merely the local fetch
	// cursor (ReaderStats.Offset is not evidence of a committed offset).
	select {
	case <-commit.committed:
	case <-ctx.Done():
		stop()
		bus.Close()
		t.Fatal("source offset not confirmed after DLQ receipt")
	}
	stop()
	bus.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("consumer did not drain")
	}
	if calls.Load() != 1 {
		t.Fatal("restart replayed quarantined business operation", calls.Load())
	}
	reader := kafka.NewReader(kafka.ReaderConfig{Brokers: []string{broker}, Topic: dlq, Partition: 0, MinBytes: 1, MaxBytes: MaximumDeadLetterBytes, MaxWait: time.Second})
	defer reader.Close()
	for i := 0; i < 2; i++ {
		m, e := reader.FetchMessage(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if string(m.Key) != id || headerValue(m.Headers, "dlq_id") != id || headerValue(m.Headers, "dlq_contract") != DeadLetterVersion {
			t.Fatal("unstable dead-letter identity")
		}
		for _, h := range m.Headers {
			if strings.Contains(string(h.Value), "PRIVATE_") {
				t.Fatal("private source/error header leaked")
			}
		}
	}
	var count int
	if e = db.QueryRowContext(ctx, sqlutil.Bind(`SELECT count(*) FROM platform_kafka_dead_letter WHERE source_id=?`), id).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate Kafka DLQs created duplicate operation records", count, e)
	}
}
