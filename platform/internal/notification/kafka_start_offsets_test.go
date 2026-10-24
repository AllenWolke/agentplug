package notification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
)

type boundaryAttemptSink struct {
	DeadLetterSink
	offsets []int64
	ack     map[int64]bool
}

func (s *boundaryAttemptSink) StartAttempt(_ context.Context, source DeadLetterSource, _ int) (DeadLetterAttempt, error) {
	s.offsets = append(s.offsets, source.Offset)
	return DeadLetterAttempt{Attempts: 1, Acknowledged: s.ack[source.Offset]}, nil
}
func (s *boundaryAttemptSink) MarkAcknowledged(_ context.Context, source DeadLetterSource) error {
	s.ack[source.Offset] = true
	return nil
}

type boundaryCommitFailure struct{ *kafkaReaderAdvancesOnFetch }

func (r boundaryCommitFailure) CommitMessages(context.Context, ...kafka.Message) error {
	return errors.New("known commit failure")
}

func TestKafkaHistoricalBoundarySkipsBeforeDecodeAndSurvivesLostGroupOffsets(t *testing.T) {
	values := []KafkaStartOffset{{Topic: "platform.audit", Partition: 0, Offset: 11}}
	minimum, err := kafkaStartOffsetMap(values)
	if err != nil {
		t.Fatal(err)
	}
	values[0].Offset = 0
	sink := &boundaryAttemptSink{ack: map[int64]bool{}}
	calls := 0
	for restart := 0; restart < 2; restart++ {
		reader := &kafkaReaderAdvancesOnFetch{messages: []kafka.Message{{Topic: "platform.audit", Partition: 0, Offset: 10, Value: []byte(`historical malformed unknown`)}, {Topic: "platform.audit", Partition: 0, Offset: 11, Value: []byte(`{"id":"new-event","tenant_id":"tenant","department_id":"department","application_id":"application","topic":"platform.audit","event_type":"probe","partition_key":"aggregate","payload":{}}`)}}}
		writer := &kafkaWriterFake{}
		bus := &KafkaGoEventBus{reader: reader, writer: writer, minimumOffsets: minimum, deadLetters: sink, group: "owned-new-group", dlqTopic: "owned-dead", max: 1, backoff: time.Nanosecond}
		err := bus.ConsumeMessages(context.Background(), func(_ context.Context, event EventMessage) DeliveryResult {
			if event.Offset != 11 {
				t.Fatal("historical record reached handler")
			}
			calls++
			return Ack()
		})
		if !errors.Is(err, errKafkaReaderDone) || len(reader.commits) != 2 || len(writer.messages) != 0 {
			t.Fatal("historical boundary or offset commit failed", err)
		}
	}
	if calls != 1 || len(sink.offsets) != 2 || sink.offsets[0] != 11 || sink.offsets[1] != 11 {
		t.Fatal("old delivery/DLQ attempt or duplicate effect occurred")
	}
}

func TestKafkaHistoricalBoundaryCommitFailureDoesNotFetchOrQuarantineNext(t *testing.T) {
	reader := &kafkaReaderAdvancesOnFetch{messages: []kafka.Message{{Topic: "platform.audit", Partition: 0, Offset: 1, Value: []byte(`unknown`)}, {Topic: "platform.audit", Partition: 0, Offset: 2, Value: []byte(`unknown`)}}}
	writer := &kafkaWriterFake{}
	sink := &boundaryAttemptSink{ack: map[int64]bool{}}
	bus := &KafkaGoEventBus{reader: boundaryCommitFailure{reader}, writer: writer, deadLetters: sink, minimumOffsets: map[kafkaPartition]int64{{"platform.audit", 0}: 2}}
	err := bus.ConsumeMessages(context.Background(), func(context.Context, EventMessage) DeliveryResult { t.Fatal("held event delivered"); return Ack() })
	if err == nil || reader.fetches != 1 || len(writer.messages) != 0 || len(sink.offsets) != 0 {
		t.Fatal("failed skip commit advanced into another operation")
	}
}

func TestKafkaHistoricalBoundaryRejectsInvalidAndForeignOffsets(t *testing.T) {
	for _, variant := range []string{"negative offset", "negative partition", "invalid topic", "duplicate partition", "foreign topic"} {
		t.Run(variant, func(t *testing.T) {
			values := []KafkaStartOffset{{Topic: "platform.audit", Partition: 0, Offset: 11}}
			switch variant {
			case "negative offset":
				values[0].Offset = -1
			case "negative partition":
				values[0].Partition = -1
			case "invalid topic":
				values[0].Topic = "platform.audit\n"
			case "duplicate partition":
				values = append(values, values[0])
			case "foreign topic":
				values[0].Topic = "foreign-topic"
			}
			_, err := NewKafkaGoEventBus(KafkaGoConfig{Brokers: []string{"127.0.0.1:9092"}, ClientID: "owned", GroupID: "owned", Topic: "platform.audit", DLQTopic: "owned-dead", MaxAttempts: 1, RetryBackoff: time.Millisecond, MinimumOffsets: values})
			if err == nil {
				t.Fatal("invalid or out-of-scope offset accepted")
			}
		})
	}
}
